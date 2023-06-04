import os
import shutil
import pefile
import peid
import subprocess
import pydumpck
import glob


def run_command(cmd):
    """
    Runs a command in the command prompt and returns the output.

    Args:
        cmd (str): Command to be executed.

    Returns:
        str: Output of the command.
    """
    return subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            shell=True,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE,
                            encoding="utf-8").communicate()


def decompyle(path):
    """
    Decompiles a Python compiled file (.pyc) using pydumpck.

    Args:
        path (str): Path to the Python compiled file (.pyc).

    Returns:
        None
    """
    print(path)
    run = run_command(["pydumpck", path])

    found = False
    output_file_path = ""
    while not found:
        for file in os.listdir():
            if "output" in file:
                found = True
                output_file_path = os.path.abspath(file)

    for filename in os.listdir(output_file_path):
        if ".pyc.cdc.py" in filename and "struct" not in filename.split(".")[0] and "pyi" not in filename.split(".")[0]:
            file_path = os.path.join(output_file_path, filename)
            shutil.move(os.path.abspath(file_path), os.getcwd() + "\\" + filename)

            # if os.path.exists(output_file_path):
            #     os.remove(output_file_path)
            # if os.path.exists("log.log"):
            #     os.remove("log.log")

            break


if __name__ == '__main__':
    decompyle("lol")
