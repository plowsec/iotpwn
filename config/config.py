import configparser
import os

current_file_path = os.path.abspath(os.path.dirname(__file__))

config = configparser.ConfigParser()
config.read(os.path.join(current_file_path, "config.cfg"))
COMMAND_EXEC_FUNCTIONS = config["recon"]["command_exec_functions"].split(",")
print(f"COMMAND_EXEC_FUNCTIONS: {COMMAND_EXEC_FUNCTIONS}")
