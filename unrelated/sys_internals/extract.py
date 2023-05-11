import os
import re
import subprocess
import psutil
import threading
import time
import logging
from dataclasses import dataclass
import string


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


def get_pid(process_name):
    for proc in psutil.process_iter():
        if proc.name() == process_name:
            return proc.pid
    return None


@dataclass
class SysInternals:
    handle_path: str = os.getcwd()[:os.getcwd().rfind("\\") + 1] + "sys_internals" + "\\handle.exe"
    strings_path: str = os.getcwd()[:os.getcwd().rfind("\\") + 1] + "sys_internals" + "\\strings.exe"

    def __init__(self):

        print(SysInternals.handle_path)

        # Set up the logging configuration
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def run_handle(self):

        process = subprocess.Popen(["virus.exe"])
        pid = get_pid("virus.exe")
        print(pid)

        with open(r"Z:\E\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\sys_internals\output_handles.txt", "w") as f:
            f.write("")

        while process.poll() is None:
            # os.system(f"handle.exe -a -p {pid} > output.txt")
            new_path = SysInternals.handle_path.replace(r"sys_internals", r"poc_start\unrelated\sys_internals")
            handle = run_command(f"{new_path} -a -p {pid}")[0]
            if "No matching handles found" in handle:
                continue
            with open(r"Z:\E\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\sys_internals\output_handles.txt", "w") as f:
                f.write(handle)
                logging.info('Checking handles...')
            time.sleep(0.2)

        # Wait for the process to finish and capture its output
        stdout, stderr = process.communicate()

        # Check the return code to see if the process completed successfully
        if process.returncode == 0:
            print("Process completed successfully.")
        else:
            print("Process failed with return code:", process.returncode)

    def run_strings(self):
        try:
            res = []
            strings = run_command(f"{SysInternals.strings_path} virus.exe")[0]
            for string in strings.split("\n"):
                # Skip strings with non-printable characters
                if not string.isprintable():
                    continue
                # Skip short strings
                if len(string) < 5:
                    continue
                if not re.match(r'^[\w\d\s.,;:?!()\-\'"]+$', string):
                    continue
                res.append(string)
            return res
        except Exception as e:
            print(f"{e} error in strings")
            return []


if __name__ == "__main__":
    pass
    s = SysInternals()
    # print(s.run_strings())
    s.run_handle()
    # handle = run_command(f"handle.exe -a -p {pid}")[0]
    # for line in handle.split("\n"):
    #     print(line)
