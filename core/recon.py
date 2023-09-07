import json
import traceback
from concurrent.futures import ThreadPoolExecutor

import r2pipe
import os
import subprocess

from typing import List, Callable, Dict, Tuple, Set, Optional

from config.config import COMMAND_EXEC_FUNCTIONS
from helpers.log import logger
import concurrent.futures
from core.pathfinder import show_paths_to_function

class FwRecon:


    @staticmethod
    def get_binaries_that_export_this_function(folder, function):

        def analyze_binary(binary, fn):
            try:
                #logger.debug(f"Analyzing {binary} for {fn}...")
                r2 = r2pipe.open(binary, flags=["-2"])
                exports = r2.cmd("iEj")

                if exports is None:
                    return False

                try:
                    exports = json.loads(exports)
                except:
                    return False

                all_exports = [export["name"] for export in exports]
                if fn in all_exports:
                    logger.info(f"Function {fn} is exported by {binary}")
                    r2.quit()
                    return True
            except:
                logger.error(f"Exception while analyzing {binary}: {traceback.format_exc()}")
            r2.quit()
            return False

        binaries = FwRecon.enumerate_binaries(folder)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(analyze_binary, binary, function) for binary in binaries}
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    logger.error(f'Generated an exception: {exc}')

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

        logger.info(f"Enumerating binaries in {path}...")

        def process_file(file):
            if FwRecon.is_executable_or_library(file):
                return file
            return None

        all_files = [os.path.join(dirpath, filename) for dirpath, dirnames, filenames in os.walk(path) for filename
                     in filenames]
        all_binaries = []

        with ThreadPoolExecutor() as executor:
            futures = {executor.submit(process_file, file) for file in all_files}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result is not None:
                        all_binaries.append(result)
                except Exception as exc:
                    logger.error(f'Generated an exception: {exc}')

        logger.info(f"Found: {all_binaries}")
        return all_binaries


    @staticmethod
    def find_interesting_binaries(binaries: List[str]) -> List[str]:
        """
        Returns a list of binaries that import interesting functions from the list COMMAND_EXEC_FUNCTIONS.
        :param binaries:
        :return:
        """
        relevant_binaries = {}  # dict of binary: list of interesting functions

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

        # log the non-empty revelant binaries as a JSON object, filter out the empty ones
        relevant_binaries = {k: v for k, v in relevant_binaries.items() if v}
        logger.info(f"Found: {relevant_binaries}")
        return relevant_binaries


    @staticmethod
    def find_binaries_with_exports_and_system(binaries: List[str]) -> List[str]:
        """
        Returns a list of binaries that contain exports and have a path to the system.
        :param binaries: list, List of binary files.
        """
        relevant_binaries = []

        for binary in binaries:
            r2 = r2pipe.open(binary)
            r2.cmd("aaa")
            exports = r2.cmdj("iEj")  # Exports as JSON

            if exports:
                for fn in COMMAND_EXEC_FUNCTIONS:
                    if show_paths_to_function(r2, binary, fn):
                        logger.log(f"Found interesting function {fn} in {binary}")
                        relevant_binaries.append(binary)
                        break

        return relevant_binaries
