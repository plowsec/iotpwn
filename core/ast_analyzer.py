import subprocess
import tempfile
import traceback
import json
import os
import typing
from collections import deque

from tree_sitter import Language, Parser

from helpers.log import logger
from core.pathfinder import is_64bit

def build_c_parser():

    build_path = "build/my-language.so"
    # check if linux but not macos
    if os.name == "posix" and os.uname().sysname == "Linux":
        build_path = "build_linux/my-language.so"

    Language.build_library(
        build_path,
        ['vendor/tree-sitter-c']
    )
    C_LANGUAGE = Language(build_path, 'c')
    parser = Parser()
    parser.set_language(C_LANGUAGE)
    return parser

def get_node_by_type(node, target_type):
    """Recursively find a child of a node with a given type."""
    # Check if the current node is of the target type
    if node.type == target_type:

        return node

    if node.type == "ERROR":
        return None

    # If not, recurse on the children of the node
    for child in node.children:
        found = get_node_by_type(child, target_type)
        if found is not None:
            return found

    # If no child of the target type is found, return None
    return None

def get_node_text(source_code, node):
    return source_code[node.start_byte:node.end_byte].decode('utf-8')


def get_function_name(source_code, node):
    """""
    name_node = get_node_text(source_code, node.child_by_field_name('declarator'))
    name_node = name_node[:name_node.index("(")].strip()
    if " " in name_node:
        name_node = name_node.split()[1]

    if hasattr(name_node, "decode"):
        return name_node.decode("utf-8")
    return name_node
    """

    if node.parent.type == "field_declaration_list":
        function_identifier_node = get_node_by_type(node, "field_identifier")
    elif function_identifier_node := get_node_by_type(node, "field_identifier"):
        pass
    else:
        function_identifier_node = get_node_by_type(node, "identifier")

    return get_node_text(source_code, function_identifier_node)

def get_child_with_partial_type(node, target_type):

    """Recursively find out if a child of a node has a type with a keyword in it."""
    if target_type in node.type:
        return node

    # If not, recurse on the children of the node
    for child in node.children:
        found = get_child_with_partial_type(child, target_type)
        if found is not None:
            return found

    # If no child of the target type is found, return None
    return None


def handle_call_expression(source_code, enclosing_function_node, enclosing_function_name, node, target_function,
                           target_parameter, pre_log):
    function_identifier_node = get_node_by_type(node, "identifier")
    function_name = get_node_text(source_code, function_identifier_node)

    logger.info(f"Found called function {function_name}")

    metrics = []
    if function_name == target_function:

        if target_parameter == "":
            pos = node.start_point
            metric = pos[1] - enclosing_function_node.start_point[1]
            metrics.append((enclosing_function_name, pre_log.copy(), metric))
            return metrics

        for child in node.children:
            if child.type != "argument_list":
                continue

            for arg in child.children:
                if arg.type != "string_literal":
                    continue

                param_value = get_node_text(source_code, arg)
                logger.info(f"Found string literal: {param_value}")

                if param_value == target_parameter:
                    logger.info(f"Found target parameter {param_value}")
                    pos = child.start_point
                    metric = pos[1] - enclosing_function_node.start_point[1]
                    metrics.append((enclosing_function_name, pre_log.copy(), metric))
                    break
            else:
                pre_log.append(function_name)
    else:
        pre_log.append(function_name)

    return metrics


def find_func_calls_in_functions(root_node, lines, target_function, target_parameter):
    function_metrics = {}

    def find_func_calls(source_code, node, pre_log):
        metrics = []
        for child in node.children:
            if child.type == "call_expression":
                metrics += handle_call_expression(source_code, enclosing_function_node, enclosing_function_name, child,
                                                  target_function, target_parameter, pre_log)
            elif child.type == "function_definition":
                return []

            metrics += find_func_calls(source_code, child, pre_log)
        return metrics

    for node in root_node.children:
        if node.type == "function_definition":
            source_code = "\n".join(lines).encode("utf-8")
            function_name = get_function_name(source_code, node)
            logger.info(f"Analyzing function {function_name}...")

            enclosing_function_node = node
            enclosing_function_name = function_name
            pre_log = []
            function_metrics[function_name] = find_func_calls(source_code, node, pre_log)

    return function_metrics


def analyze_code(csv_path, binary_name, code: str, target_function, target_parameter) -> list:
    parser = build_c_parser()

    tree = parser.parse(bytes(code, "utf8"))
    lines = code.split("\n")
    metrics_array = find_func_calls_in_functions(tree.root_node, lines, target_function, target_parameter)

    for function, metrics in metrics_array.items():
        if len(metrics) == 0:
            continue

        print(f"Metrics for function {function}: {metrics}")
        line, functions_called_before, metric = metrics[0][0], metrics[0][1], metrics[0][2]
        print(f"Match found in function: {line}, metric: {metric}, functions called before: {functions_called_before}")
        with open(csv_path, "a") as f:
            f.write(f"{binary_name},{function},{metric},{functions_called_before}\n")

    return metrics_array


def decompile(binary: str) -> (str, str):

    """
    Decompiles the given binary and returns the decompiled code.
    :param binary: absolute path to the binary to decompile
    :return: the decompiled code
    """


    try:
        idat_path = "idat64" if is_64bit(binary) else "idat"

        logger.info(f"Decompiling {binary}...")
        output_file = tempfile.NamedTemporaryFile(suffix=".c", delete=False)
        command = f"{idat_path} -Ohexrays:{output_file.name}:ALL -A {binary}"
        subprocess.run(command, shell=True)

        # read and return the output file
        with open(output_file.name, "r") as f:
            return f.read(), output_file.name
    except:
        logger.error(f"Exception while decompiling {binary}: {traceback.format_exc()}")
        return "", ""


def read_cache(cache_file: str) -> dict:
    """
    Reads the cache from a given JSON file.
    :param cache_file: Path to the JSON cache file
    :return: Dictionary with cache data
    """
    if os.path.exists(cache_file):
        with open(cache_file, "r") as f:
            return json.load(f)
    return {}


def write_cache(cache_file: str, cache_data: dict) -> None:
    """
    Writes the cache data to a given JSON file.
    :param cache_file: Path to the JSON cache file
    :param cache_data: Dictionary with cache data
    """
    with open(cache_file, "w") as f:
        json.dump(cache_data, f)


def batch_decompile(binaries: list, cache_file="decompile_cache.json") -> typing.Dict[str, str]:
    """
    Decompiles a list of binaries and caches the results.
    :param binaries: List of paths to the binaries
    :param cache_file: Path to the cache JSON file
    """

    cache_data = read_cache(cache_file)

    for binary in binaries:
        if binary in cache_data:
            print(f"Decompiled code for {binary} is cached.")
            continue

        decompiled_code, decompiled_path = decompile(binary)
        if len(decompiled_code) > 0:
            # Assume `write_decompiled_to_file()` saves the decompiled code to a file
            # and returns the path to this file
            cache_data[binary] = decompiled_path

            write_cache(cache_file, cache_data)

    return cache_data
