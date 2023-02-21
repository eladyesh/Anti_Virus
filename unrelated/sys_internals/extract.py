import os

import pefile
import peid
import subprocess
import psutil
import threading
import time
import logging

# Set up the logging configuration
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')



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


if __name__ == "__main__":

    # strings = run_command(f"strings.exe virus.exe")[0]
    # for string in strings.split("\n"):
    #     print(string)

    process = subprocess.Popen(["virus.exe"])
    pid = get_pid("virus.exe")
    print(pid)

    with open("output_handles.txt", "w") as f:
        f.write("")

    while process.poll() is None:
        # os.system(f"handle.exe -a -p {pid} > output.txt")
        handle = run_command(f"handle.exe -a -p {pid}")[0]
        with open("output_handles.txt", "w") as f:
            f.write(handle)
            logging.info('Checking handles...')
        time.sleep(0.01)

    # Wait for the process to finish and capture its output
    stdout, stderr = process.communicate()

    # Check the return code to see if the process completed successfully
    if process.returncode == 0:
        print("Process completed successfully.")
    else:
        print("Process failed with return code:", process.returncode)

    # handle = run_command(f"handle.exe -a -p {pid}")[0]
    # for line in handle.split("\n"):
    #     print(line)
