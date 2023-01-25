import os
import shutil

import pefile
import peid
import subprocess
import pydumpck
import glob


def run_command(cmd):
    """
    runs cmd command in the command prompt and returns the output
    arg: cmd
    ret: the output of the command
    """
    return subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            shell=True,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE,
                            encoding="utf-8").communicate()


def decompyle():
    run = run_command(
        f"pydumpck D:\\Cyber\\YB_CYBER\\project\\FinalProject\\poc_start\\poc_start\\unrelated\\python_exe\\virus.exe")

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
            shutil.move(file_path, os.getcwd())
            break


if __name__ == '__main__':
    decompyle()
