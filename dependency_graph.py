import json
import os
import r2pipe
import networkx as nx


import networkx as nx
from rich import print
from rich.tree import Tree
from typing import List
from dataclasses import dataclass


@dataclass
class Function:
    name: str
    binary: str


@dataclass
class Binary:
    name: str
    imports: set
    exports: set


class DependencyGraph:

    all_binaries = []
    binaries: List[Binary] = []

    def __init__(self, path):
        self.enumerate_binaries(path)
        # self.binaries_with_exports = self.find_binaries_with_exports_and_system(self.all_binaries, self.find_paths_to)
        self.G = self.build_dependency_graph(self.all_binaries)
        self.sorted_binaries = self.topologically_sort_graph(self.G)
        self.function_graphs = self.build_function_graphs(self.sorted_binaries)
        self.find_all_paths_across_binaries(self.function_graphs, "main", "sym.imp.execl")

    def enumerate_binaries(self, path):

        for dirpath, dirnames, filenames in os.walk(path):
            for file in filenames:
                if os.access(os.path.join(dirpath, file), os.X_OK):
                    self.all_binaries.append(os.path.join(dirpath, file))

        print(f"Found: {self.all_binaries}")


    def find_binaries_with_exports_and_system(self, binaries, find_paths_to):
        relevant_binaries = []

        for binary in binaries:
            r2 = r2pipe.open(binary)
            exports = r2.cmdj("iEj")  # Exports as JSON

            if exports:
                if find_paths_to(binary, "system"):
                    relevant_binaries.append(binary)

        return relevant_binaries


    def build_dependency_graph(self, binaries):
        G = nx.DiGraph()
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
                    print(lib)
                    full_path = basename_to_fullpath[basename]
                    dependencies_to_keep.append(full_path)
                    G.add_edge(binary, full_path)
                else:
                    print(f"Skipping {lib} because it is not in the list of binaries")



        print(f"Dependency graph:")
        for node in G.nodes:
            print(self.build_rich_tree(G, node))
        return G


    def topologically_sort_graph(self, G):
        return list(nx.topological_sort(G))


    def find_exporting_binary(self, function_name, all_binaries):
        for binary in all_binaries:
            if function_name in binary.exports:
                return binary.name
        return None


    def find_path_between_functions(self, func_G, start, end):
        try:
            return nx.shortest_path(func_G, start, end)
        except nx.NetworkXNoPath:
            return None


    def simplify_name(self, function_name):
        return function_name.replace("sym.imp.", "").replace("sym.", "").replace("imp.", "")

    def get_function_list(self, binary):
        r2 = r2pipe.open(binary, flags=["-2"])  # disable errors
        r2.cmd("aaa")

        # Get the list of functions and exports
        functions = r2.cmdj("aflj")

        exports = {exp['name'] for exp in r2.cmdj("iEj")}  # Keep exported function names in a set
        exports.add("main")

        return r2, functions, exports

    def create_graph(self, functions, binary):
        G = nx.DiGraph()
        for function in functions:
            fn_name = self.simplify_name(function['name'])
            G.add_node((fn_name, binary))
        return G

    def save_path(self, new_path, name, binary, G):
        if len(new_path) > 1:
            for i in range(len(new_path) - 1):
                G.add_edge(new_path[i], new_path[i + 1])
        elif new_path[0] != (name, binary):
            G.add_edge(new_path[0], (name, binary))


    def process_reference(self, r2, binary, unsanitized_name, exports, new_path, G):
        name = self.simplify_name(unsanitized_name)

        if name in new_path:
            return

        corresponding_node = self.find_corresponding_node(name, binary, G)

        if corresponding_node is not None:
            if name in exports:  # If this function is exported, save the path
                self.save_path(new_path, name, binary, G)
            else:
                self.find_paths(r2, binary, unsanitized_name, new_path, exports, G)


    def get_library_if_imported(self, current_function_name, binary):

        fn_and_binary_names = (current_function_name, binary)
        for bin_name in self.binaries:
            found = False
            if current_function_name in bin_name.imports:
                print(f"Function {current_function_name} is imported by {bin_name.name}")
                for bin2 in self.binaries:
                    if bin2.name == bin_name.name:
                        continue
                    if current_function_name in bin2.exports:
                        print(f"Function {current_function_name} is exported by {bin2.name}")
                        fn_and_binary_names = (current_function_name, bin2.name)
                        found = True
                        break
                if found:
                    break

        return fn_and_binary_names


    def find_paths(self, r2, binary, current_function: str, path, exports, G):

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
            self.process_reference(r2, binary, unsanitized_name, exports, path + [current_tuple], G)

    def add_paths_to_graph(self, r2, binary, functions, exports, G):


        for function in functions:
            self.find_paths(r2, binary, function['name'], [], exports, G)
        return G

    def build_function_graphs(self, binaries):
        function_graphs = {}

        for binary in binaries:
            print(f"Analyzing {binary}")

            r2, functions, exports = self.get_function_list(binary)
            G = self.create_graph(functions, binary)
            G = self.add_paths_to_graph(r2, binary, functions, exports, G)

            function_graphs[binary] = G

            for node in G.nodes:
                if G.out_degree(node) > 0:
                    print(self.build_rich_tree(G, node))

        return function_graphs

    def find_path_in_binary(self, binary_graphs, binary, start_func, end_func):
        # Ensure the binary and the functions exist
        if binary not in binary_graphs or not binary_graphs[binary].has_node(start_func) or not binary_graphs[binary].has_node(end_func):
            return None

        try:
            # Use NetworkX to find a path between the two functions
            return nx.shortest_path(binary_graphs[binary], start_func, end_func)
        except nx.NetworkXNoPath:
            return None


    def find_path_across_binaries(self, binary_graphs, start_func, end_func):
        # Aggregate all the graphs into a single graph
        aggregate_graph = nx.DiGraph()

        for binary, graph in binary_graphs.items():
            aggregate_graph = nx.compose(aggregate_graph, graph)

        try:
            # Use NetworkX to find a path between the two functions
            return nx.shortest_path(aggregate_graph, start_func, end_func)
        except nx.NetworkXNoPath:
            return None


    def find_all_paths_across_binaries(self, binary_graphs, start_func, end_func):
        # Aggregate all the graphs into a single graph
        aggregate_graph = nx.DiGraph()

        for binary, graph in binary_graphs.items():
            aggregate_graph = nx.compose(aggregate_graph, graph)

        print(f"Aggregate graph across all binaries:")
        for node in aggregate_graph.nodes:
            # only print if the node has edges
            if aggregate_graph.out_degree(node) > 0:
                if node[0] in ["system", "popen", "execl", "exec", "execve", "memcpy"]:
                    print(self.build_rich_tree(aggregate_graph, node))

        # Use NetworkX to find all paths between the two functions
        all_paths = list(nx.all_simple_paths(aggregate_graph, start_func, end_func))

        return all_paths


    def build_rich_tree(self, graph, node, tree=None):
        if tree is None:
            tree = Tree(str(node))

        for child in graph.successors(node):
            subtree = Tree(str(child))
            tree.add(subtree)
            self.build_rich_tree(graph, child, subtree)

        return tree

    def find_corresponding_node(self, name, binary, G):

        for b in self.sorted_binaries:
            if G.has_node((name, b)):
                return (name, b)
        return None


    """
    def find_paths(binary, current_function, path):

        current_function_name = self.simplify_name(current_function)
        current_tuple = (current_function_name, binary)

        for bin_name in self.binaries:
            found = False
            if current_function_name in bin_name.imports:
                print(f"Function {current_function_name} is imported by {bin_name.name}")
                for bin2 in self.binaries:
                    if bin2.name == bin_name.name:
                        continue
                    if current_function_name in bin2.exports:
                        print(f"Function {current_function_name} is exported by {bin2.name}")
                        current_tuple = (current_function_name, bin2.name)
                        found = True
                        break
                if found:
                    break

        if current_tuple in path:
            print(f"Found a cycle: {path}")
            return

        # Get all references to this function
        refs = r2.cmdj(f"axtj @ {current_function}")

        if len(refs) == 0:
            print(f"No more xrefs to {current_function} {path}")
            return

        for ref in refs:
            unsanitized_name = ref['fcn_name'] if 'fcn_name' in ref else ref['refname']
            name = self.simplify_name(unsanitized_name)

            if name in path:
                print(
                    f"Skipping {name} because it is the same as the current function: {path}, name: {name} current_function_name: {current_function_name}")
                print(refs)
                continue

            corresponding_node = self.find_corresponding_node(name, binary, G)

            if corresponding_node is not None:
                new_path = path + [current_tuple]
                if name in exports:  # If this function is exported, save the path
                    if len(new_path) > 1:
                        for i in range(len(new_path) - 1):
                            # print(f"Adding codepath: {new_path[i]} -> {new_path[i + 1]}")
                            G.add_edge(new_path[i], new_path[i + 1])
                    elif new_path[0] != (name, binary):
                        # print(f"Adding codepath simple: {new_path[0]} -> {(name, binary)}")
                        G.add_edge(new_path[0], (name, binary))
                else:
                    find_paths(binary, unsanitized_name, new_path)
    """
