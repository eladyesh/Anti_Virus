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
    Runs a command in the command prompt and returns the output.

    Args:
        cmd (str): The command to run.

    Returns:
        str: The output of the command.
    """
    return subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            shell=True,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE,
                            encoding="utf-8").communicate()


def get_pid(process_name):
    """
    Retrieves the process ID (PID) of a given process name.

    Args:
        process_name (str): The name of the process.

    Returns:
        int or None: The PID of the process if found, None otherwise.
    """
    for proc in psutil.process_iter():
        if proc.name() == process_name:
            return proc.pid
    return None


@dataclass
class SysInternals:
    """
    A class representing the SysInternals tools.

    Attributes:
        handle_path (str): The path to the handle.exe tool.
        strings_path (str): The path to the strings.exe tool.
    """
    handle_path: str = os.getcwd()[:os.getcwd().rfind("\\") + 1] + "sys_internals" + "\\handle.exe"
    strings_path: str = os.getcwd()[:os.getcwd().rfind("\\") + 1] + "sys_internals" + "\\strings.exe"

    def __init__(self):
        """
        Initializes the SysInternals class.

        This method sets up the logging configuration.
        """
        print(SysInternals.handle_path)

        # Set up the logging configuration
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def run_handle(self):
        """
        Runs the handle.exe tool and captures the output.

        This method starts a subprocess of a hypothetical "virus.exe" program, retrieves its PID,
        and uses handle.exe to monitor its handles. The output is written to a file.

        Note: The actual implementation of the "virus.exe" program is not provided.

        """
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
        """
        Runs the strings command on the "virus.exe" file and returns a list of printable strings.
        Returns a filtered list based on file size and allowed string patterns if it's a Python file.
        Returns an empty list if an error occurs.
        """
        size = os.path.getsize("virus.exe") / 1024
        py_file = False
        py_allowed = ["py", "Py", "ctypes", "string", "socket", "pickle", "subprocess",
                      "get", "copy", "base64", "argparse", "api", "kernel32", "GetProcAddress", 'GetExitCodeProcess',
                      'CreateProcessW', 'GetStartupInfoW', 'FreeLibrary', 'LoadLibraryExW', 'SetConsoleCtrlHandler',
                      'FindClose', 'FindFirstFileExW',
                      'CloseHandle', 'GetCurrentProcess', 'LocalFree', 'FormatMessageW', 'MultiByteToWideChar',
                      'WideCharToMultiByte', 'KERNEL32.dll',
                      'OpenProcessToken', 'GetTokenInformation', 'ConvertSidToStringSidW',
                      'ConvertStringSecurityDescriptorToSecurityDescriptorW',
                      'ADVAPI32.dll', 'RtlCaptureContext', 'RtlLookupFunctionEntry', 'RtlVirtualUnwind',
                      'UnhandledExceptionFilter', 'SetUnhandledExceptionFilter',
                      'TerminateProcess', 'IsProcessorFeaturePresent', 'QueryPerformanceCounter', 'GetCurrentProcessId',
                      'GetCurrentThreadId', 'GetSystemTimeAsFileTime',
                      'InitializeSListHead', 'IsDebuggerPresent', 'GetModuleHandleW', 'RtlUnwindEx', 'SetLastError',
                      'EnterCriticalSection', 'LeaveCriticalSection', 'DeleteCriticalSection',
                      'InitializeCriticalSectionAndSpinCount', 'TlsAlloc', 'TlsGetValue', 'TlsSetValue', 'TlsFree',
                      'EncodePointer', 'RaiseException', 'RtlPcToFileHeader', 'GetCommandLineA',
                      'CreateFileW', 'GetDriveTypeW', 'GetFileInformationByHandle', 'GetFileType', 'PeekNamedPipe',
                      'SystemTimeToTzSpecificLocalTime', 'FileTimeToSystemTime', 'GetFullPathNameW',
                      'RemoveDirectoryW', 'FindNextFileW', 'SetStdHandle', 'DeleteFileW', 'ReadFile', 'GetStdHandle',
                      'WriteFile', 'ExitProcess', 'GetModuleHandleExW', 'HeapFree', 'GetConsoleMode',
                      'ReadConsoleW', 'SetFilePointerEx', 'GetConsoleOutputCP', 'GetFileSizeEx', 'HeapAlloc',
                      'FlsAlloc', 'FlsGetValue', 'FlsSetValue', 'FlsFree', 'CompareStringW', 'LCMapStringW',
                      'GetCurrentDirectoryW', 'FlushFileBuffers', 'HeapReAlloc', 'GetFileAttributesExW',
                      'GetStringTypeW', 'IsValidCodePage', 'GetACP', 'GetOEMCP', 'GetCPInfo', 'GetEnvironmentStringsW',
                      'FreeEnvironmentStringsW', 'GetProcessHeap', 'GetTimeZoneInformation', 'HeapSize',
                      'WriteConsoleW', 'SetEndOfFile']
        py_not_allowed = ['PyOBX)', 'pyR-E', 'pylqTg', 'pyNsy', 'PyQ.u', 'gAPyKU', 'NYnppPy', 'NpyJ"', 'VPyjA', 'pyZdL', 'py_?7', 'PyaeA', 'PyW:ng', 'EtTpy', 'tlpyp49', '_compat_pickle)', '_py_abc)']
        if size > 6000:
            py_file = True
        try:
            res = []
            res_py = []
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
                if py_file:
                    if any(s in string for s in py_allowed) and "Failed" not in string \
                            and "api" not in string and "Fls" not in string and \
                            "es" not in string and "Tls" not in string and "pyd" not in string\
                            and "pyz" not in string and string not in py_not_allowed:
                        res_py.append(string)
                res.append(string)
            if py_file:
                return res_py[4:]
            else:
                return res[:225]
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
