import os
import traceback

import r2pipe
from helpers.log import logger


def analyze_binary(binary_path):
    r2 = r2pipe.open(binary_path)
    r2.cmd('aaa')
    return r2


def get_func_addr(r2, func_name):
    imports = r2.cmdj('iij')
    for imp in imports:
        if imp['name'] == func_name:
            return imp['plt']
    return None


def get_xrefs_to(r2, addr):
    return r2.cmdj(f'axtj @ {addr}')


def find_paths_to_func(r2, target_func_addr, visited=None, path=None):
    if path is None:
        path = []

    if visited is None:
        visited = set()

    # Base case: the target function is reached
    if target_func_addr in visited:
        return []

    # Add the current function to the path
    path = path + [target_func_addr]

    visited.add(target_func_addr)

    # Recursively follow all callers of the current function
    callers = get_xrefs_to(r2, target_func_addr)

    paths = []

    for caller in callers:
        if 'fcn_addr' in caller and caller['fcn_addr'] not in visited:  # Check if the function is visited
            logger.info(f"Found xref to {hex(target_func_addr)}: {caller}. path= {' -> '.join(hex(addr) for addr in path)}")

            # if has_dynamic_argument(r2, caller):
            #    logger.info(f"Found dynamic argument in {caller}")

            newpaths = find_paths_to_func(r2, caller['fcn_addr'], visited, path)
            for newpath in newpaths:
                paths.append(newpath)

    if not paths:
        return [path]
    else:
        return paths


def get_imported_libraries(r2):
    # Get imported libraries
    libraries = r2.cmdj('ilj')

    return libraries


def get_imported_functions(r2):
    # Get imported functions
    functions = r2.cmdj('iij')

    return functions



def walk_directory(directory, function):
    for folder_name, subfolders, file_names in os.walk(directory):
        for file_name in file_names:
            full_path = os.path.join(folder_name, file_name)
            if os.access(full_path, os.X_OK):
                r2 = analyze_binary(full_path)
                paths = find_paths_to_func(r2, function)
                if paths:
                    logger.info(f"In binary {full_path}, paths to function {function}:")
                    for path in paths:
                        logger.info(" -> ".join(path))
                r2.quit()


def find_sources(r2):

    sources = {}

    all_fns = r2.cmdj("aflj")
    for fn in all_fns:
        if "main" in fn["name"]:
            logger.info(fn)
            sources[fn["offset"]] = fn["name"]

    all_exported_fn = r2.cmdj("iEj")
    for fn in all_exported_fn:
        sources[fn["vaddr"]] = fn["name"]

    return sources


def show_paths_to_function(r2, binary, function):

    fn_addr = get_func_addr(r2, function)
    if fn_addr is None:
        #logger.info("This function is never called by the binary")
        return
    paths = find_paths_to_func(r2, fn_addr)
    all_sources = find_sources(r2)
    if paths:
        logger.info(f"In binary {binary}, paths to function {function}:")
        for path in paths:
            is_from_source = False
            if any(p in all_sources for p in path):
                try:
                    logger.info(f"Reachable from this source: {all_sources[path[-1]]}")
                except:
                    logger.error(traceback.format_exc())
                    logger.error(list(all_sources.keys()))
                    logger.error(path)
                    reachable_from = [all_sources[p] for p in path if p in all_sources]
                    logger.info(f"Reachable from: {reachable_from}")
            logger.info(" -> ".join(hex(addr) for addr in path))
    else:
        logger.info(f"No paths found to function {function} in binary {binary}")


def get_arg_register(arch_info):
    arch = arch_info.get('bin', {}).get('arch')
    bits = arch_info.get('bin', {}).get('bits')
    if arch == 'x86':
        return 'esp' if bits == 32 else 'rdi'
    return None


def has_dynamic_argument(r2, xref):
    arg_register = get_arg_register(r2.cmdj('ij'))
    r2.cmd(f's {xref["from"]}')

    # Analyze 10 instructions prior to the function call
    disasm = r2.cmdj("pdj -10")

    print("Instructions prior to the function call:")
    for ins in disasm:
        print(ins.get('opcode'))

    print("Instructions prior to the function call (ESIL):")
    for ins in disasm:
        if ins.get('type') in ['mov', 'lea']:
            arg = ins.get('esil')
            if arg:
                dest, src = arg.split(",", 1)
                if dest == arg_register:
                    arg_type = "Static" if 'str.' in src else "Dynamic"
                    print(f"[{arg_type}] Argument to system in {xref['fcn_name']} at offset {ins['offset']}: {src}")
                    return arg_type == "Dynamic"

