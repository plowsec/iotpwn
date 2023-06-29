import r2pipe
import os
import subprocess

from typing import List, Callable, Dict, Tuple, Set, Optional

from config.config import COMMAND_EXEC_FUNCTIONS
from helpers.log import logger


class FwRecon:



    @staticmethod
    def is_executable_or_library(filepath: str) -> bool:
        """Determines if the given filepath points to an executable or a library."""

        # Run the 'file' command and get its output
        result = subprocess.run(['file', filepath], capture_output=True, text=True)

        # Parse the output
        output = result.stdout.lower()

        # Check if the file is an executable or library
        return 'executable' in output or 'shared object' in output

    @staticmethod
    def enumerate_binaries(path: str) -> List[str]:

        """
        Walks through a given path and appends any executables to the list 'all_binaries'.
        :param path: str, The file system path to walk through.
        """

        all_binaries = []

        for dirpath, dirnames, filenames in os.walk(path):
            for file in filenames:
                if FwRecon.is_executable_or_library(os.path.join(dirpath, file)):
                    all_binaries.append(os.path.join(dirpath, file))

        logger.info(f"Found: {all_binaries}")
        return all_binaries


    @staticmethod
    def find_interesting_binaries(binaries: List[str]) -> List[str]:
        """
        Returns a list of binaries that import interesting functions from the list COMMAND_EXEC_FUNCTIONS.
        :param binaries:
        :return:
        """
        relevant_binaries = {} # dict of binary: list of interesting functions

        for binary in binaries:
            r2 = r2pipe.open(binary, flags=["-2"])
            imports = r2.cmdj("iij")
            relevant_binaries[binary] = []

            if imports:
                all_imports_as_string = [imp["name"] for imp in imports]
                for fn in COMMAND_EXEC_FUNCTIONS:
                    if fn in all_imports_as_string:
                        logger.info(f"Found interesting function {fn} in {binary}")
                        relevant_binaries[binary].append(fn)
        logger.info(f"Found: {relevant_binaries}")


    @staticmethod
    def find_binaries_with_exports_and_system(binaries: List[str], find_paths_to: Callable) -> List[str]:
        """
        Returns a list of binaries that contain exports and have a path to the system.
        :param binaries: list, List of binary files.
        :param find_paths_to: function, Function to determine paths to the system.
        """
        relevant_binaries = []

        for binary in binaries:
            r2 = r2pipe.open(binary)
            exports = r2.cmdj("iEj")  # Exports as JSON

            if exports:
                for fn in COMMAND_EXEC_FUNCTIONS:
                    if find_paths_to(binary, fn):
                        logger.log(f"Found interesting function {fn} in {binary}")
                        relevant_binaries.append(binary)
                        break

        return relevant_binaries
