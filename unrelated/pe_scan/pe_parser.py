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


path_to_pe_scan = "exe\\peScan.exe"
path_to_virus = "exe\\virus.exe"
a = run_command("exe\\peScan.exe" + " " + "exe\\virus.exe")[0]
print(a)