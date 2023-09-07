import argparse


from core.dependency_graph import DependencyGraph
from core.recon import FwRecon
from helpers.log import logger
from config.config import COMMAND_EXEC_FUNCTIONS
from core.pathfinder import analyze_binary, get_imported_libraries, get_imported_functions, show_paths_to_function, walk_directory


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--binary", help="Path to the binary to analyze")
    parser.add_argument("-d", "--directory", help="Path to the directory to analyze")
    parser.add_argument("-f", "--function", help="Name of the function to find paths to")
    parser.add_argument("-l", "--libraries", action="store_true", help="List all imported libraries")
    parser.add_argument("-i", "--imports", action="store_true", help="List all imported functions")
    parser.add_argument("-a", "--auto", action="store_true", help="Autopwn")
    parser.add_argument("-r", "--recon", action="store_true", help="Enumerate all interesting binaries in the folder")
    parser.add_argument("-e", "--export", action="store_true", help="Find which binary exports the provided function")

    # add an argument for finding libraries that have paths between exports and interesting functions
    parser.add_argument("-R", "--recon2", action="store_true", help="Enumerate all binaries in the folder and find paths between exports and interesting functions")

    args = parser.parse_args()

    if args.binary:
        r2 = analyze_binary(args.binary)
        if args.function:
            show_paths_to_function(r2, args.binary, args.function)

        elif args.libraries:
            libraries = get_imported_libraries(r2)
            logger.info(f"Imported libraries: {libraries}")

        elif args.imports:
            functions = get_imported_functions(r2)
            logger.info(f"Imported functions: {functions}")

        r2.quit()

    if args.directory and args.function and not args.export:
        walk_directory(args.directory, args.function)

    elif args.directory and args.recon2:
        binaries = FwRecon.enumerate_binaries(args.directory)
        only_interesting_binaries = FwRecon.find_interesting_binaries(binaries)
        FwRecon.find_binaries_with_exports_and_system(only_interesting_binaries)

    elif args.directory and args.auto:

        logger.info("Autopwning...")
        DependencyGraph(args.directory)
    elif args.directory and args.recon:
        logger.info("Recon...")
        binaries = FwRecon.enumerate_binaries(args.directory)
        FwRecon.find_interesting_binaries(binaries)

    elif args.export and args.function:
        FwRecon.get_binaries_that_export_this_function(args.directory, args.function)



if __name__ == "__main__":
    main()
