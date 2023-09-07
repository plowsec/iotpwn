import subprocess
import tempfile
import traceback

from helpers.log import logger


def decompile(binary: str) -> str:

    """
    Decompiles the given binary and returns the decompiled code.
    :param binary: absolute path to the binary to decompile
    :return: the decompiled code
    """

    try:
        output_file = tempfile.NamedTemporaryFile(suffix=".c")
        command = f"idat64 -Ohexrays:{output_file.name}:ALL -A {binary}"
        subprocess.run(command, shell=True)

        # read and return the output file
        with open(output_file.name, "r") as f:
            return f.read()
    except:
        logger.error(f"Exception while decompiling {binary}: {traceback.format_exc()}")
        return ""
