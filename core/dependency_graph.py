import os
import r2pipe
import networkx as nx

from rich import print
from rich.tree import Tree
from typing import List, Callable, Dict, Tuple, Set, Optional

from helpers.log import logger
from core.models import Binary, Function



class DependencyGraph:

    all_binaries = []
    binaries: List[Binary] = []

    def __init__(self, path):
        self.enumerate_binaries(path)
        # self.binaries_with_exports = self.find_binaries_with_exports_and_system(self.all_binaries, self.find_paths_to)
        self.functions_digraph = self.build_dependency_graph(self.all_binaries)
        self.sorted_binaries = self.topologically_sort_graph(self.functions_digraph)
        self.function_graphs = self.build_function_graphs(self.sorted_binaries)
        self.find_all_paths_across_binaries(self.function_graphs, "main", "sym.imp.execl")


    def enumerate_binaries(self, path: str) -> None:

        """
        Walks through a given path and appends any executables to the list 'all_binaries'.
        :param path: str, The file system path to walk through.
        """
        for dirpath, dirnames, filenames in os.walk(path):
            for file in filenames:
                if os.access(os.path.join(dirpath, file), os.X_OK):
                    self.all_binaries.append(os.path.join(dirpath, file))

        logger.info(f"Found: {self.all_binaries}")


    def build_dependency_graph(self, binaries: List[str]) -> nx.DiGraph:

        """
        Builds a directed graph to show the dependencies between different binaries.
        :param binaries: list, List of binary files.
        """
        functions_digraph = nx.DiGraph()
        basename_to_fullpath = {os.path.basename(path): path for path in self.all_binaries}

        for binary in binaries:
            r2 = r2pipe.open(binary)
            imported_libs = r2.cmdj("ilj")  # Imports as JSON
            # Create a dictionary to map basenames to full paths
            exports = {exp['name'] for exp in r2.cmdj("iEj")}  # Keep exported function names in a set
            exports.add("main")
            imports = {imp['name'] for imp in r2.cmdj("iij")}  # Keep imported function names in a set
            bin = Binary(name=binary, imports=imports, exports=exports)
            self.binaries.append(bin)

            dependencies_to_keep = []

            for lib in imported_libs:
                basename = os.path.basename(lib)
                if basename in basename_to_fullpath:
                    logger.info(lib)
                    full_path = basename_to_fullpath[basename]
                    dependencies_to_keep.append(full_path)
                    functions_digraph.add_edge(binary, full_path)
                else:
                    logger.info(f"Skipping {lib} because it is not in the list of binaries")

        logger.info(f"Dependency graph:")
        for node in functions_digraph.nodes:
            print(self.build_rich_tree(functions_digraph, node))
        return functions_digraph


    def topologically_sort_graph(self, functions_digraph: nx.DiGraph) -> List:

        """
         Returns a topologically sorted list from a directed graph of functions.
         :param functions_digraph: networkx.DiGraph, Directed graph of functions.
         """

        return list(nx.topological_sort(functions_digraph))


    def find_exporting_binary(self, function_name: str, all_binaries: List[Binary]) -> str:

        """
        Finds and returns the binary which exports a given function.
        :param function_name: str, Name of the function to find.
        :param all_binaries: list, List of all binaries.
        """
        for binary in all_binaries:
            if function_name in binary.exports:
                return binary.name
        return None


    def find_path_between_functions(self, function_digraph: nx.DiGraph, start: str, end: str) -> List[str]:

        """
        Returns the shortest path between 'start' and 'end' in a given function graph.
        :param function_digraph: networkx.DiGraph, Directed graph of functions.
        :param start: str, Start function name.
        :param end: str, End function name.
        """
        try:
            return nx.shortest_path(function_digraph, start, end)
        except nx.NetworkXNoPath:
            return []


    def simplify_name(self, function_name: str) -> str:
        """
        Simplifies the function name by removing certain prefixes.
        :param function_name: str, Name of the function to simplify.
        """
        return function_name.replace("sym.imp.", "").replace("sym.", "").replace("imp.", "")


    def get_function_list(self, binary: str):

        """
        Returns a list of functions and exports for a given binary.
        :param binary: str, Binary file name.
        """
        r2 = r2pipe.open(binary, flags=["-2"])  # disable errors
        r2.cmd("aaa")

        # Get the list of functions and exports
        functions = r2.cmdj("aflj")

        exports = {exp['name'] for exp in r2.cmdj("iEj")}  # Keep exported function names in a set
        exports.add("main")

        return r2, functions, exports


    def create_graph(self, functions: List[Dict], binary: str) -> nx.DiGraph:
        """
        Creates a directed graph of functions for a given binary.
        :param functions: list, List of functions.
        :param binary: str, Binary file name.
        """
        functions_digraph = nx.DiGraph()
        for function in functions:
            fn_name = self.simplify_name(function['name'])
            functions_digraph.add_node((fn_name, binary))
        return functions_digraph


    def save_path(self, new_path: List[str], name: str, binary: str, functions_digraph: nx.DiGraph) -> None:
        """
        Saves the path between functions in a directed graph.
        :param new_path: list, New path to be added.
        :param name: str, Function name.
        :param binary: str, Binary file name.
        :param functions_digraph: networkx.DiGraph, Directed graph of functions.
        """
        if len(new_path) > 1:
            for i in range(len(new_path) - 1):
                functions_digraph.add_edge(new_path[i], new_path[i + 1])
        elif new_path[0] != (name, binary):
            functions_digraph.add_edge(new_path[0], (name, binary))


    def process_reference(self, r2, binary: str, unsanitized_name: str, exports: Set[str], new_path: List[str],
                          functions_digraph: nx.DiGraph) -> None:

        """
        Processes a reference, either saving the path or finding further paths.
        :param r2: r2pipe object, Instance of the r2pipe class.
        :param binary: str, Binary file name.
        :param unsanitized_name: str, The unsanitized name of the function.
        :param exports: set, Set of exported function names.
        :param new_path: list, New path to be added.
        :param functions_digraph: networkx.DiGraph, Directed graph of functions.
        """
        name = self.simplify_name(unsanitized_name)

        if name in new_path:
            return

        corresponding_node = self.find_corresponding_node(name, binary, functions_digraph)

        if corresponding_node is not None:
            if name in exports:  # If this function is exported, save the path
                self.save_path(new_path, name, binary, functions_digraph)
            else:
                self.find_paths(r2, binary, unsanitized_name, new_path, exports, functions_digraph)


    def get_library_if_imported(self, current_function_name: str, binary: str) -> Tuple[str, str]:
        """
        Returns a tuple of function name and the binary if the function is imported.
        :param current_function_name: str, Name of the current function.
        :param binary: str, Binary file name.
        """
        fn_and_binary_names = (current_function_name, binary)
        for bin_name in self.binaries:
            found = False
            if current_function_name in bin_name.imports:
                logger.info(f"Function {current_function_name} is imported by {bin_name.name}")
                for bin2 in self.binaries:
                    if bin2.name == bin_name.name:
                        continue
                    if current_function_name in bin2.exports:
                        logger.info(f"Function {current_function_name} is exported by {bin2.name}")
                        fn_and_binary_names = (current_function_name, bin2.name)
                        found = True
                        break
                if found:
                    break

        return fn_and_binary_names


    def find_paths(self, r2, binary: str, current_function: str, path: List[str], exports: Set[str],
                   functions_digraph: nx.DiGraph) -> None:
        """
        Finds paths in a binary starting from the current function.
            :param r2: r2pipe object, Instance of the r2pipe class.
            :param binary: str, Binary file name.
            :param current_function: str, The current function.
            :param path: list, Current path being built.
            :param exports: set, Set of exported function names.
            :param functions_digraph: networkx.DiGraph, Directed graph of functions.
        """

        current_function_name = self.simplify_name(current_function)
        current_tuple = self.get_library_if_imported(current_function_name, binary)

        if current_tuple in path:
            return

        # Get all references to this function
        refs = r2.cmdj(f"axtj @ {current_function}")

        if len(refs) == 0:
            return

        for ref in refs:
            unsanitized_name = ref['fcn_name'] if 'fcn_name' in ref else ref['refname']
            self.process_reference(r2, binary, unsanitized_name, exports, path + [current_tuple], functions_digraph)


    def add_paths_to_graph(self, r2, binary: str, functions: List[str], exports: Set[str],
                           functions_digraph: nx.DiGraph) -> nx.DiGraph:
        """
        Adds paths from all functions to a directed graph.
        :param r2: r2pipe object, Instance of the r2pipe class.
        :param binary: str, Binary file name.
        :param functions: list, List of functions.
        :param exports: set, Set of exported function names.
        :param functions_digraph: networkx.DiGraph, Directed graph of functions.
        """
        for function in functions:
            self.find_paths(r2, binary, function['name'], [], exports, functions_digraph)
        return functions_digraph


    def build_function_graphs(self, binaries: List[str]) -> Dict[str, nx.DiGraph]:
        """
        Builds a dictionary of function graphs for all binaries.
        :param binaries: list, List of binary files.
        """
        function_graphs = {}

        for binary in binaries:
            logger.info(f"Analyzing {binary}")

            r2, functions, exports = self.get_function_list(binary)
            functions_digraph = self.create_graph(functions, binary)
            functions_digraph = self.add_paths_to_graph(r2, binary, functions, exports, functions_digraph)
            function_graphs[binary] = functions_digraph

        return function_graphs


    def find_path_in_binary(self, binary_graphs: Dict[str, nx.DiGraph], binary: str, start_func: str, end_func: str) -> \
    List[str]:
        """
        Finds a path between two functions within a binary.
        :param binary_graphs: dict, Dictionary of binary graphs.
        :param binary: str, Binary file name.
        :param start_func: str, Start function name.
        :param end_func: str, End function name.
        """

        # Ensure the binary and the functions exist
        if binary not in binary_graphs or not binary_graphs[binary].has_node(start_func) or not binary_graphs[binary].has_node(end_func):
            return []

        try:
            # Use NetworkX to find a path between the two functions
            return nx.shortest_path(binary_graphs[binary], start_func, end_func)
        except nx.NetworkXNoPath:
            return []


    def find_path_across_binaries(self, binary_graphs: Dict[str, nx.DiGraph], start_func: str, end_func: str) -> List[
        str]:
        """
        Finds a path between two functions across different binaries.
        :param binary_graphs: dict, Dictionary of binary graphs.
        :param start_func: str, Start function name.
        :param end_func: str, End function name.
        """
        # Aggregate all the graphs into a single graph
        aggregate_graph = nx.DiGraph()

        for binary, graph in binary_graphs.items():
            aggregate_graph = nx.compose(aggregate_graph, graph)

        try:
            # Use NetworkX to find a path between the two functions
            return nx.shortest_path(aggregate_graph, start_func, end_func)
        except nx.NetworkXNoPath:
            return []


    def find_all_paths_across_binaries(self, binary_graphs: Dict[str, nx.DiGraph], start_func: str, end_func: str) -> \
    List[List[str]]:
        """
        Finds all paths between two functions across different binaries.
        :param binary_graphs: dict, Dictionary of binary graphs.
        :param start_func: str, Start function name.
        :param end_func: str, End function name.
        """
        # Aggregate all the graphs into a single graph
        aggregate_graph = nx.DiGraph()

        for binary, graph in binary_graphs.items():
            aggregate_graph = nx.compose(aggregate_graph, graph)

        logger.info(f"Aggregate graph across all binaries:")
        for node in aggregate_graph.nodes:

            # only print if the node has edges
            if aggregate_graph.out_degree(node) > 0:
                if node[0] in ["system", "popen", "execl", "exec", "execve", "memcpy"]:
                    print(self.build_rich_tree(aggregate_graph, node))

        # find all paths between the two functions
        all_paths = list(nx.all_simple_paths(aggregate_graph, start_func, end_func))

        return all_paths


    def build_rich_tree(self, graph: nx.DiGraph, node: str, tree: Optional[Tree] = None) -> Tree:
        """
        Recursively builds a rich tree for a given node in a graph.
        :param graph: networkx.DiGraph, Directed graph of functions.
        :param node: str, The node to build the tree from.
        :param tree: RichTree, Optional, The tree to add to.
        """
        if tree is None:
            tree = Tree(str(node))

        for child in graph.successors(node):
            subtree = Tree(str(child))
            tree.add(subtree)
            self.build_rich_tree(graph, child, subtree)

        return tree


    def find_corresponding_node(self, name: str, binary: str, functions_digraph: nx.DiGraph) -> Tuple[str, str]:

        """
        Finds and returns a node in the function digraph that matches the name and binary.
        :param name: str, Function name.
        :param binary: str, Binary file name.
        :param functions_digraph: networkx.DiGraph, Directed graph of functions.
        """

        for b in self.sorted_binaries:
            if functions_digraph.has_node((name, b)):
                return name, b
        return None


    """
    def find_paths(binary, current_function, path):

        current_function_name = self.simplify_name(current_function)
        current_tuple = (current_function_name, binary)

        for bin_name in self.binaries:
            found = False
            if current_function_name in bin_name.imports:
                logger.info(f"Function {current_function_name} is imported by {bin_name.name}")
                for bin2 in self.binaries:
                    if bin2.name == bin_name.name:
                        continue
                    if current_function_name in bin2.exports:
                        logger.info(f"Function {current_function_name} is exported by {bin2.name}")
                        current_tuple = (current_function_name, bin2.name)
                        found = True
                        break
                if found:
                    break

        if current_tuple in path:
            logger.info(f"Found a cycle: {path}")
            return

        # Get all references to this function
        refs = r2.cmdj(f"axtj @ {current_function}")

        if len(refs) == 0:
            logger.info(f"No more xrefs to {current_function} {path}")
            return

        for ref in refs:
            unsanitized_name = ref['fcn_name'] if 'fcn_name' in ref else ref['refname']
            name = self.simplify_name(unsanitized_name)

            if name in path:
                logger.info(
                    f"Skipping {name} because it is the same as the current function: {path}, name: {name} current_function_name: {current_function_name}")
                logger.info(refs)
                continue

            corresponding_node = self.find_corresponding_node(name, binary, functions_digraph)

            if corresponding_node is not None:
                new_path = path + [current_tuple]
                if name in exports:  # If this function is exported, save the path
                    if len(new_path) > 1:
                        for i in range(len(new_path) - 1):
                            # logger.info(f"Adding codepath: {new_path[i]} -> {new_path[i + 1]}")
                            functions_digraph.add_edge(new_path[i], new_path[i + 1])
                    elif new_path[0] != (name, binary):
                        # logger.info(f"Adding codepath simple: {new_path[0]} -> {(name, binary)}")
                        functions_digraph.add_edge(new_path[0], (name, binary))
                else:
                    find_paths(binary, unsanitized_name, new_path)
    """
