import ast
import inspect
import os
import re
import subprocess
import requests
from bs4 import BeautifulSoup
from decompile_exe import *


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
        response = requests.get("https://learn.microsoft.com/en-us/windows/win32/procthread/process-and-thread-functions")
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
        return ""
        url = f"https://docs.microsoft.com/en-us/windows/win32/api/{winap_func.lower()}"
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
        return calls

    def log_for_winapi(self, calls):

        # Use regular expression to match the function names and their parameters
        pattern = re.compile(r"(\w+)\s*=\s*ctypes\.windll\.(\w+)\.(\w+)\((.*)\)")

        with open("log.txt", "w") as file:
            functions_dict = {}
            for match in pattern.finditer(calls):
                library_name = match.group(2)
                function_name = match.group(3)
                parameters = match.group(4)
                file.write(f"Library name: {library_name}\n")
                file.write(f"Function name: {function_name}\n")
                file.write(f"Parameters: {parameters}\n")
                file.write("\n")

                # Add function to dictionary
                if function_name in functions_dict:
                    functions_dict[function_name].append(parameters)
                else:
                    functions_dict[function_name] = [parameters]
            print(functions_dict)
            # TODO - additional checks on the functions dict

    def check_for_keylogger(self):

        self.keylogger_detected = 0
        self.suspicious_imoprts_for_keylogger = ['PIL', 'requests', 'cryptography.fernet', 'sounddevice', 'scipy.io'
                                                                                                          '.wavfile',
                                                 'pynput.keyboard', 'win32clipboard',
                                                 'platform', 'socket', 'smtplib', 'email', 'email.mime.base',
                                                 'email.mime.text', 'email.mime.multipart']

        self.suspicious_funcs = ['MIMEMultipart', 'getpass.getuser', 'time.time', 's.starttls', 'socket.gethostname', 'attachment.read',
                                 'Listener', 'listener.join', 'screenshot', 'win32clipboard.OpenClipboard', 'win32clipboard.GetClipboardData',
                                 'win32clipboard.CloseClipboard', 'platform.processor', 'platform.system', 'platform'
                                                                                                           '.version', 'platform.machine',
                                 'send_mail', 'Fernet', 'ImageGrab.grab', 'smtplib.SMTP', 'MIMEText']

        self.suspicious_functions_and_params = {'MIMEBase': ['application', 'octet-stream'], 'open': ['attachment', 'rb'],
                                                'socket.gethostbyname': 'hostname'}

        self.suspicious_regex_patterns = [re.compile(r'(\w+)\.starttls'), re.compile(r'(\w+)\.set_payload'),
                                          re.compile(r'(\w+)\.encrypt'), re.compile(r'(\w+)\.login'), re.compile(r'(\w+)\.rec'),
                                          re.compile(r'(\w+)\.wait'), re.compile(r'(\w+)\.encode_base64'), re.compile(r'(\w+)\.add_header')]

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
    print(pv.find_ctypes_calls())
    pv.log_for_winapi(pv.find_ctypes_calls())
    # pv.crawl_for_winapi()
    # print(PythonVirus.scrape_for_info("CreateFileA"))