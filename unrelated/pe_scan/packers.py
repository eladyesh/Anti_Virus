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


a = run_command("peid nop.exe")[0]
packers = []
for i in a.split("\n")[:-1]:
    packers.append(i)

print(packers)