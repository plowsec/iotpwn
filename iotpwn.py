import argparse
import os
import r2pipe

from dependency_graph import DependencyGraph


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
            print(f"Found xref to {hex(target_func_addr)}: {caller}. path= {' -> '.join(hex(addr) for addr in path)}")
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
                    print(f"In binary {full_path}, paths to function {function}:")
                    for path in paths:
                        print(" -> ".join(path))
                r2.quit()


def find_sources(r2):

    sources = {}

    all_fns = r2.cmdj("aflj")
    for fn in all_fns:
        if "main" in fn["name"]:
            print(fn)
            sources[fn["offset"]] = fn["name"]

    all_exported_fn = r2.cmdj("iEj")
    for fn in all_exported_fn:
        sources[fn["vaddr"]] = fn["name"]

    return sources


def show_paths_to_function(r2, args):

    fn_addr = get_func_addr(r2, args.function)
    if fn_addr is None:
        print("This function is never called by the binary")
        return
    paths = find_paths_to_func(r2, fn_addr)
    all_sources = find_sources(r2)
    if paths:
        print(f"In binary {args.binary}, paths to function {args.function}:")
        for path in paths:
            is_from_source = False
            if any(p in all_sources for p in path):
                print(f"Reachable from this source: {all_sources[path[-1]]}")
            print(" -> ".join(hex(addr) for addr in path))
    else:
        print(f"No paths found to function {args.function} in binary {args.binary}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--binary", help="Path to the binary to analyze")
    parser.add_argument("-d", "--directory", help="Path to the directory to analyze")
    parser.add_argument("-f", "--function", help="Name of the function to find paths to")
    parser.add_argument("-l", "--libraries", action="store_true", help="List all imported libraries")
    parser.add_argument("-i", "--imports", action="store_true", help="List all imported functions")
    parser.add_argument("-a", "--auto", action="store_true", help="Autopwn")
    args = parser.parse_args()

    if args.binary:
        r2 = analyze_binary(args.binary)
        if args.function:
            show_paths_to_function(r2, args)

        elif args.libraries:
            libraries = get_imported_libraries(r2)
            print(f"Imported libraries: {libraries}")

        elif args.imports:
            functions = get_imported_functions(r2)
            print(f"Imported functions: {functions}")
        r2.quit()

    if args.directory and args.function:

       walk_directory(args.directory, args.function)
    elif args.directory and args.auto:

        print("Autopwning...")
        DependencyGraph(args.directory)

if __name__ == "__main__":
    main()