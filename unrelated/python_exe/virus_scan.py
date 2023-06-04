import ast
import inspect
import os
import re
import subprocess
import requests
from bs4 import BeautifulSoup
from poc_start.unrelated.python_exe.decompile_exe import *
import threading
import psutil
import glob
# from googlesearch import search
from ast import For, Tuple, List
import pydumpck
import logging

logging.basicConfig(level=logging.WARNING)


def get_loop_params(path):
    """
    Extracts loop parameters from a Python file.

    Args:
        path (str): Path to the Python file.

    Returns:
        list: List of loop parameters.
    """
    with open(path, "r") as f:
        tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.For):
                loop_params = []
                for i in node.body:
                    if isinstance(i, ast.Name):
                        loop_params.append(i.id)
                if not loop_params:
                    if isinstance(node.iter, ast.Tuple):
                        return [e.n for e in node.iter.elts]
                return loop_params


class PythonVirus:
    """
    PythonVirus class for analyzing and manipulating Python source code.
    """
    def __init__(self, file):
        """
        Initializes the PythonVirus instance.

        Args:
            file (str): Path to the Python file.
        """
        self.path = os.path.abspath(file)
        decompyle(self.path)

        for filename in os.listdir(os.getcwd()):
            if ".pyc.cdc.py" in filename:
                self.file = filename
                break

        # Load the source code of the Python file
        with open(os.path.abspath(self.file), "r") as f:
            self.source = f.read()

        # Parse the source code
        self.tree = ast.parse(self.source)

    def crawl_for_winapi(self):
        """
        Crawls web pages to extract WinAPI function names and saves them to a file.
        """
        # request the page
        # response_file = requests.get("https://docs.microsoft.com/en-us/windows/win32/fileio/file-management-functions")
        # response_sock = requests.get("https://docs.microsoft.com/en-us/windows/win32/fileio/winsock-functions")
        # response_registry = requests.get("https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-functions")
        # response_keyboard = requests.get("https://learn.microsoft.com/en-us/windows/win32/inputdev/keyboard-input")
        # response_memory = requests.get("https://learn.microsoft.com/en-us/windows/win32/memory/memory-management-functions")
        response = requests.get(
            "https://learn.microsoft.com/en-us/windows/win32/procthread/process-and-thread-functions")
        soup = BeautifulSoup(response.text, 'html.parser')

        functions = soup.find_all("tr")
        funcs = []
        for function in functions:
            name = function.find("td")
            if name:
                funcs.append(name.text)

        with open("winapi_funcs/thread_functions.txt", "w") as file:
            for function in funcs:
                file.write(function + "\n")

    def get_imports(self):
        """
        Extracts import statements from the Python source code.

        Returns:
            list: List of imported modules.
        """
        imports = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)

            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module)
        return imports

    @staticmethod
    def scrape_for_info(winap_func):
        """
        Scrapes information from web pages based on the WinAPI function name.

        Args:
            winap_func (str): WinAPI function name.

        Returns:
            str: Scraped information.
        """
        def get_first_result(query):
            for url in search(query):
                return url

        func_name = winap_func
        url = get_first_result(func_name)

        page = requests.get(url)
        soup = BeautifulSoup(page.content, 'html.parser')
        soup_str = soup.prettify()
        content_start = soup_str.find("<content>")
        content_end = soup_str.find("</content>")
        content_str = soup_str[content_start:content_end]
        p_start = content_str.find("<p>")
        p_end = content_str.find("</p>")
        p_tag = content_str[p_start:p_end + 4]
        p_text = p_tag.strip().replace("<p>", "").split(".")[0]
        return p_text.strip()

    def find_line_of_variable(self, variable):
        """
        Finds the line containing the given variable in the Python source code.

        Args:
            variable (str): Variable name to search for.

        Returns:
            str or False: The line containing the variable, or False if not found.
        """
        with open(self.file, "r") as f:
            source_code = f.read()
            lines = source_code.split("\n")
            for i, line in enumerate(lines):
                match = re.search(r'\b' + variable + r'\b', line)
                if match:
                    return line

        return False

    def find_ctypes_calls(self):
        """
        Searches for ctypes function calls in the Python source code.

        Returns:
            list: List of ctypes function calls.
        """
        if "ctypes" not in self.get_imports():
            return []

        def find_winapi_calls(code_path, winapi_functions):
            winapi_calls = []
            for function in winapi_functions:
                # run the grep command
                # result = subprocess.run(["grep", "-r", function, code_path], capture_output=True, text=True)
                result = subprocess.run(["findstr", "/s", "/i", function, code_path], capture_output=True, text=True)

                # add the results to the winapi_calls list
                calls = result.stdout.strip().split("\n")
                winapi_calls.extend(calls)
            return winapi_calls

        winapi_functions = []
        for file in os.listdir(os.path.abspath("winapi_funcs").replace("graphics", "python_exe")):
            with open(os.path.abspath("winapi_funcs").replace("graphics", "python_exe") + "\\" + file, "r") as f:
                try:
                    for line in f:
                        name = line.strip()
                        winapi_functions.append(name)
                except UnicodeError:
                    continue
        # print(winapi_functions)

        # code_path = "D:\\Cyber\\YB_CYBER\\project\\FinalProject\\poc_start\\poc_start\\unrelated\\python_exe\\test.py"
        winapi_calls = find_winapi_calls(self.file, winapi_functions)

        calls = ''''''
        for call in winapi_calls:
            if call != "":
                calls += call + "\n"

        return "\n".join(list(set(calls.split("\n"))))

    @staticmethod
    def make_function_dict():
        """
        Creates a dictionary of function names and their corresponding search results.

        Returns:
            dict: Dictionary of function names and search results.
        """
        def get_first_result(query):
            """
            Retrieves the first search result URL for the given query.

            Args:
                query (str): Query string to search for.

            Returns:
                str: The URL of the first search result.
            """
            for url in search(query):
                return url

        def search_for_file_functions():
            """
            Searches for file-related functions and adds them to the function_dict.
            """
            function_dict = {}
            with open("winapi_funcs" + "\\" + "file_functions.txt", "r") as file:
                for line in file:
                    line = line.strip()
                    function_dict[line] = get_first_result(line)
                    print("Done with ", line)

        def search_for_keyboard_functions():
            """
            Searches for keyboard-related functions and adds them to the function_dict.
            """
            function_dict = {}
            with open("winapi_funcs" + "\\" + "keboard_functions.txt", "r") as file:
                for line in file:
                    line = line.strip()
                    function_dict[line] = get_first_result(line)
                    print("Done with ", line)

        def search_for_memory_functions():
            """
            Searches for memory-related functions and adds them to the function_dict.
            """
            function_dict = {}
            with open("winapi_funcs" + "\\" + "memory_functions.txt", "r") as file:
                for line in file:
                    line = line.strip()
                    function_dict[line] = get_first_result(line)
                    print("Done with ", line)
            print(function_dict)

        def search_for_registry_functions():
            """
            Searches for registry-related functions and adds them to the function_dict.
            """
            function_dict = {}
            with open("winapi_funcs" + "\\" + "registry_functions.txt", "r") as file:
                for line in file:
                    line = line.strip()
                    function_dict[line] = get_first_result(line)
                    print("Done with ", line)
            print(function_dict)

        def search_for_thread_functions():
            """
            Searches for thread-related functions and adds them to the function_dict.
            """
            function_dict = {}
            with open("winapi_funcs" + "\\" + "thread_functions.txt", "r") as file:
                for line in file:
                    line = line.strip()
                    function_dict[line] = get_first_result(line)
                    print("Done with ", line)
            print(function_dict)

        def search_for_winsock_functions():
            """
            Searches for winsock-related functions and adds them to the function_dict.
            """
            function_dict = {}
            with open("winapi_funcs" + "\\" + "winsock_functions.txt", "r") as file:
                for line in file:
                    line = line.strip()
                    function_dict[line] = get_first_result(line)
                    print("Done with ", line)
            print(function_dict)

        thread1 = threading.Thread(target=search_for_file_functions)
        thread2 = threading.Thread(target=search_for_thread_functions)
        thread3 = threading.Thread(target=search_for_winsock_functions)
        thread4 = threading.Thread(target=search_for_keyboard_functions)
        thread5 = threading.Thread(target=search_for_memory_functions)
        thread6 = threading.Thread(target=search_for_registry_functions)

        thread1.start()
        thread2.start()
        thread3.start()
        thread4.start()
        thread5.start()
        thread6.start()

        thread1.join()
        thread2.join()
        thread3.join()
        thread4.join()
        thread5.join()
        thread6.join()

    def log_for_winapi(self, calls):
        """
        Logs WinAPI function calls and performs analysis.

        Args:
            calls (str): The string representation of the WinAPI function calls.

        Returns:
            None

        """
        if calls == []:
            with open(os.getcwd() + "\\log_python.txt", "a") as file:
                file.write("")
            return

        # Use regular expression to match the function names and their parameters
        pattern = re.compile(r"(\w+)\s*=\s*ctypes\.windll\.(\w+)\.(\w+)\((.*)\)|ctypes\.windll\.(\w+)\.(\w+)\((.*)\)")

        functions_dict = {}
        with open(os.getcwd() + "\\log_python.txt", "a") as file:
            for match in pattern.finditer(calls):

                # Extract the matched groups from the regular expression
                if match.group(1) is None:
                    variable_name = ""
                else:
                    variable_name = match.group(1)
                if match.group(2) is None:
                    library_name = match.group(5)
                else:
                    library_name = match.group(2)
                if match.group(3) is None:
                    function_name = match.group(6)
                else:
                    function_name = match.group(3)
                if match.group(4) is None:
                    parameters = match.group(7)
                else:
                    parameters = match.group(4)
                file.write(f"Variable name: {variable_name}\n")
                file.write(f"Library name: {library_name}\n")
                file.write(f"Function name: {function_name}\n")
                file.write(f"Parameters: {parameters}\n")
                file.write("\n")

                # Add function to dictionary
                if function_name in functions_dict:
                    functions_dict[function_name].append(parameters)
                else:
                    functions_dict[function_name] = [param.strip() for param in parameters.split(",")]

            # Check for injection
            if 'VirtualAllocEx' in functions_dict.keys() and 'WriteProcessMemory' in functions_dict.keys():
                if functions_dict['VirtualAllocEx'][0] == functions_dict['WriteProcessMemory'][0]:

                    match = re.search(r'\((.*?)\)', functions_dict['OpenProcess'][-1])
                    if match:
                        pid_name = match.group(1)

                    pid_line = self.find_line_of_variable(pid_name)
                    pid = None
                    exec(pid_line, {"os": os})
                    process = psutil.Process(pid)
                    file.write("==============INJECTION==============\n")
                    file.write(f"Found Injection to process: {process.name()}\n")
                    file.write(f"PID: {str(process.pid)}\n")
                    file.write(f"Parent PID: {str(process.pid)}\n")

                    data_line = self.find_line_of_variable(functions_dict["WriteProcessMemory"][2])
                    file.write(f"The data being injected: {data_line.split('=')[1].strip()}\n")
                    file.write("==============INJECTION==============\n\n")

            # Port scan
            # Use regular expression to match the function names, parameters, and result
            pattern = re.compile(r"(\w+)\s*=\s*winsock\.(\w+)\((.*)\)|winsock\.(\w+)\((.*)\)")

            with open(os.path.join(os.getcwd(), "log_python.txt"), "a") as file:
                for match in pattern.finditer(calls):
                    variable_name = match.group(1) if match.group(1) else None
                    function_name = match.group(2) if match.group(2) else match.group(4)
                    parameters = match.group(3) if match.group(3) else match.group(5)
                    functions_dict[function_name] = [param.strip() for param in parameters.split(",") if param.strip()]

                    file.write(f"Variable name: {variable_name}\n") if variable_name else None
                    file.write(f"Library name: winsock\n")
                    file.write(f"Function name: {function_name}\n")
                    file.write(f"Parameters: {parameters}\n")
                    file.write("\n")

                print(functions_dict, os.path.abspath("log_python.txt"))

                if 'socket' in functions_dict.keys() and 'connect' in functions_dict.keys() and 'getaddrinfo' in functions_dict.keys():
                    file.write("==============PORT SCANNING==============\n")
                    file.write(f"Trying to scan through ports {get_loop_params(self.file)}\n")

                    # Website
                    web_line = self.find_line_of_variable(functions_dict['getaddrinfo'][0])
                    file.write(f"Trying to connect to website {web_line.split('=')[1].strip()}\n")
                    file.write("==============PORT SCANNING==============\n\n")

                # Registry virus
                if 'RegCloseKey' in functions_dict.keys() and 'RegCreateKeyExW' in functions_dict.keys() and 'RegOpenKeyExW' in functions_dict.keys() and 'RegSetValueExW' in functions_dict.keys():
                    file.write("==============REGISTRY CHANGE==============\n")

                    shell = self.find_line_of_variable(functions_dict['RegOpenKeyExW'][1]).split("=")[1].strip()
                    file.write(f"Trying to add or change key {shell}\n")
                    file.write(f"Trying to add key {functions_dict['RegCreateKeyExW'][1]}\n")

                    exe = self.find_line_of_variable(functions_dict['RegSetValueExW'][-2]).split("=")[1].strip()
                    file.write(f"Trying to set key to {exe}\n")
                    file.write("==============REGISTRY CHANGE==============\n\n")

    def check_for_keylogger(self):
        """
        Checks for the presence of keylogger-related suspicious activities in Python code.

        Args:
            tree (ast.Module): The abstract syntax tree (AST) representing the Python code.

        Returns:
            Tuple: A tuple containing lists of various suspicious findings, including suspicious imports,
                   suspicious function calls, suspicious function calls with specific parameters,
                   suspicious regex patterns, and suspicious function parameters.
        """
        self.keylogger_detected = 0
        self.suspicious_imoprts_for_keylogger = ['PIL', 'requests', 'cryptography.fernet', 'sounddevice', 'scipy.io'
                                                                                                          '.wavfile',
                                                 'pynput.keyboard', 'win32clipboard',
                                                 'platform', 'socket', 'smtplib', 'email', 'email.mime.base',
                                                 'email.mime.text', 'email.mime.multipart']
        self.suspect_imports_found = []

        self.suspicious_funcs = ['MIMEMultipart', 'getpass.getuser', 'time.time', 's.starttls', 'socket.gethostname',
                                 'attachment.read',
                                 'Listener', 'listener.join', 'screenshot', 'win32clipboard.OpenClipboard',
                                 'win32clipboard.GetClipboardData',
                                 'win32clipboard.CloseClipboard', 'platform.processor', 'platform.system', 'platform'
                                                                                                           '.version',
                                 'platform.machine',
                                 'send_mail', 'Fernet', 'ImageGrab.grab', 'smtplib.SMTP', 'MIMEText']
        self.suspicious_funcs_found = []

        self.suspicious_functions_and_params = {'MIMEBase': ['application', 'octet-stream'],
                                                'open': ['attachment', 'rb'],
                                                'socket.gethostbyname': 'hostname'}
        self.suspicious_functions_and_params_found = {}

        self.suspicious_regex_patterns = [re.compile(r'(\w+)\.starttls'), re.compile(r'(\w+)\.set_payload'),
                                          re.compile(r'(\w+)\.encrypt'), re.compile(r'(\w+)\.login'),
                                          re.compile(r'(\w+)\.rec'), re.compile(r'(\w+)\.attach'),
                                          re.compile(r'(\w+)\.wait'), re.compile(r'(\w+)\.encode_base64'),
                                          re.compile(r'(\w+)\.add_header')]
        self.suspicious_regex_patterns_found = []

        self.suspicious_params = ['Keys', 'keys', 'space', 'Key', 'key', 'k']
        self.suspicious_params_found = []

        # imports
        for imp in self.get_imports():
            if imp in self.suspicious_imoprts_for_keylogger:
                self.suspect_imports_found.append(imp)

        # Find the Call node that represents the open function
        for node in ast.walk(self.tree):

            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    # func_name = node.func.attr
                    try:
                        func_name = f"{node.func.value.id}.{node.func.attr}"
                    except AttributeError:
                        print('attribute error')

                # Extract the arguments passed to the function
                args = [arg.id if isinstance(arg, ast.Name) else arg.s if isinstance(arg, ast.Str) else None for arg in
                        node.args]

                # Print the function name and arguments
                logging.warning(f"Function '{func_name}' called with arguments {args}")

                if func_name in self.suspicious_funcs:
                    self.suspicious_funcs_found.append(func_name)

                if func_name in self.suspicious_functions_and_params.keys() and args in self.suspicious_functions_and_params.values():
                    self.suspicious_functions_and_params_found[func_name] = args

                for pattern in self.suspicious_regex_patterns:
                    match = pattern.search(func_name)
                    if match:
                        self.suspicious_regex_patterns_found.append(match.group())

                for arg in args:
                    if arg in self.suspicious_params:
                        self.suspicious_params_found.append(arg)

        return (self.suspect_imports_found,
                self.suspicious_funcs_found,
                self.suspicious_functions_and_params_found,
                self.suspicious_regex_patterns_found,
                self.suspicious_params_found)


if __name__ == "__main__":
    pass
    # pv = PythonVirus("keylogger.exe")
    # print(pv.get_imports())
    # pv.check_for_keylogger()
    # print(pv.find_ctypes_calls())
    # pv.log_for_winapi(pv.find_ctypes_calls())
    # pv.crawl_for_winapi()
    # print(PythonVirus.scrape_for_info("CreateFileA"))
    # PythonVirus.make_function_dict()
