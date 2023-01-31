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
from ast import For, Tuple, List
import pydumpck


def get_loop_params(path):
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

    def __init__(self, file):

        self.path = os.path.abspath(file)
        decompyle(self.path)

        for filename in os.listdir(os.getcwd()):
            if ".pyc.cdc.py" in filename:
                self.file = filename
                break

        # Load the source code of the Python file
        with open(self.file, "r") as f:
            self.source = f.read()

        # Parse the source code
        self.tree = ast.parse(self.source)

    def crawl_for_winapi(self):

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

        with open(self.file, "r") as f:
            source_code = f.read()
            lines = source_code.split("\n")
            for i, line in enumerate(lines):
                match = re.search(r'\b' + variable + r'\b', line)
                if match:
                    return line

        return False

    def find_ctypes_calls(self):

        def find_winapi_calls(code_path, winapi_functions):
            winapi_calls = []
            for function in winapi_functions:
                # run the grep command
                result = subprocess.run(["grep", "-r", function, code_path], capture_output=True, text=True)
                # add the results to the winapi_calls list
                calls = result.stdout.strip().split("\n")
                winapi_calls.extend(calls)
            return winapi_calls

        winapi_functions = []
        for file in os.listdir(os.path.abspath("winapi_funcs")):
            with open("winapi_funcs" + "\\" + file, "r") as f:
                for line in f:
                    name = line.strip()
                    winapi_functions.append(name)
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

        def get_first_result(query):
            for url in search(query):
                return url

        def search_for_file_functions():
            function_dict = {}
            with open("winapi_funcs" + "\\" + "file_functions.txt", "r") as file:
                for line in file:
                    line = line.strip()
                    function_dict[line] = get_first_result(line)
                    print("Done with ", line)

        def search_for_keyboard_functions():
            function_dict = {}
            with open("winapi_funcs" + "\\" + "keboard_functions.txt", "r") as file:
                for line in file:
                    line = line.strip()
                    function_dict[line] = get_first_result(line)
                    print("Done with ", line)

        def search_for_memory_functions():
            function_dict = {}
            with open("winapi_funcs" + "\\" + "memory_functions.txt", "r") as file:
                for line in file:
                    line = line.strip()
                    function_dict[line] = get_first_result(line)
                    print("Done with ", line)
            print(function_dict)

        def search_for_registry_functions():
            function_dict = {}
            with open("winapi_funcs" + "\\" + "registry_functions.txt", "r") as file:
                for line in file:
                    line = line.strip()
                    function_dict[line] = get_first_result(line)
                    print("Done with ", line)
            print(function_dict)

        def search_for_thread_functions():
            function_dict = {}
            with open("winapi_funcs" + "\\" + "thread_functions.txt", "r") as file:
                for line in file:
                    line = line.strip()
                    function_dict[line] = get_first_result(line)
                    print("Done with ", line)
            print(function_dict)

        def search_for_winsock_functions():
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

        # Use regular expression to match the function names and their parameters
        pattern = re.compile(r"(\w+)\s*=\s*ctypes\.windll\.(\w+)\.(\w+)\((.*)\)|ctypes\.windll\.(\w+)\.(\w+)\((.*)\)")

        functions_dict = {}
        with open("log.txt", "a") as file:
            for match in pattern.finditer(calls):
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

            # check for injection
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

            # port scan
            # Use regular expression to match the function names, parameters, and result
            pattern = re.compile(r"(\w+)\s*=\s*winsock\.(\w+)\((.*)\)|winsock\.(\w+)\((.*)\)")

            with open("log.txt", "a") as file:
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

                print(functions_dict)

                if 'socket' in functions_dict.keys() and 'connect' in functions_dict.keys() and 'getaddrinfo' in functions_dict.keys():
                    file.write("==============PORT SCANNING==============\n")
                    file.write(f"Trying to scan through ports {get_loop_params(self.file)}\n")

                    # website
                    web_line = self.find_line_of_variable(functions_dict['getaddrinfo'][0])
                    file.write(f"Trying to connect to website {web_line.split('=')[1].strip()}\n")
                    file.write("==============PORT SCANNING==============\n\n")

                # registry virus
                if 'RegCloseKey' in functions_dict.keys() and 'RegCreateKeyExW' in functions_dict.keys() and 'RegOpenKeyExW' in functions_dict.keys() and 'RegSetValueExW' in functions_dict.keys():
                    file.write("==============REGISTRY CHANGE==============\n")

                    shell = self.find_line_of_variable(functions_dict['RegOpenKeyExW'][1]).split("=")[1].strip()
                    file.write(f"Trying to add or change key {shell}\n")
                    file.write(f"Trying to add key {functions_dict['RegCreateKeyExW'][1]}\n")

                    exe = self.find_line_of_variable(functions_dict['RegSetValueExW'][-2]).split("=")[1].strip()
                    file.write(f"Trying to set key to {exe}\n")
                    file.write("==============REGISTRY CHANGE==============\n\n")


def check_for_keylogger(self):
    self.keylogger_detected = 0
    self.suspicious_imoprts_for_keylogger = ['PIL', 'requests', 'cryptography.fernet', 'sounddevice', 'scipy.io'
                                                                                                      '.wavfile',
                                             'pynput.keyboard', 'win32clipboard',
                                             'platform', 'socket', 'smtplib', 'email', 'email.mime.base',
                                             'email.mime.text', 'email.mime.multipart']

    self.suspicious_funcs = ['MIMEMultipart', 'getpass.getuser', 'time.time', 's.starttls', 'socket.gethostname',
                             'attachment.read',
                             'Listener', 'listener.join', 'screenshot', 'win32clipboard.OpenClipboard',
                             'win32clipboard.GetClipboardData',
                             'win32clipboard.CloseClipboard', 'platform.processor', 'platform.system', 'platform'
                                                                                                       '.version',
                             'platform.machine',
                             'send_mail', 'Fernet', 'ImageGrab.grab', 'smtplib.SMTP', 'MIMEText']

    self.suspicious_functions_and_params = {'MIMEBase': ['application', 'octet-stream'],
                                            'open': ['attachment', 'rb'],
                                            'socket.gethostbyname': 'hostname'}

    self.suspicious_regex_patterns = [re.compile(r'(\w+)\.starttls'), re.compile(r'(\w+)\.set_payload'),
                                      re.compile(r'(\w+)\.encrypt'), re.compile(r'(\w+)\.login'),
                                      re.compile(r'(\w+)\.rec'),
                                      re.compile(r'(\w+)\.wait'), re.compile(r'(\w+)\.encode_base64'),
                                      re.compile(r'(\w+)\.add_header')]

    self.suspicious_params = ['Keys', 'keys', 'space', 'Key', 'key', 'k']

    # imports
    self.imp_counter = 0
    for imp in self.get_imports():
        if imp in self.suspicious_imoprts_for_keylogger:
            self.imp_counter += 1

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
            print(f"Function '{func_name}' called with arguments {args}")

            # if func_name == "open":
            #     # The first argument of the open function is the file name
            #     file_name = node.args[0]
            #     print(f"File name: {file_name.s}")
            #
            #     # The second argument of the open function is the mode
            #     mode = node.args[1]
            #     print(f"Mode: {mode.s}")
            #
            # if func_name == "write":
            #     # The first argument of the write function is the string to be written
            #
            #     string_to_write = node.args[0]
            #
            #     print(f"String to write: {string_to_write.s}")


if __name__ == "__main__":
    pv = PythonVirus("virus.exe")
    # print(pv.get_imports())
    # pv.check_for_keylogger()
    # print(pv.find_ctypes_calls())
    pv.log_for_winapi(pv.find_ctypes_calls())
    # pv.crawl_for_winapi()
    # print(PythonVirus.scrape_for_info("CreateFileA"))
    # PythonVirus.make_function_dict()
