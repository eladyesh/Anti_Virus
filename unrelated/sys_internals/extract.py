import os

import pefile
import peid
import subprocess


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


if __name__ == "__main__":
    strings = run_command(f"Strings/strings.exe virus.exe")[0]
    print(strings.split("\n"))
