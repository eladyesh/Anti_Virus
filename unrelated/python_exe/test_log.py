import re

calls = '''
file_handle = ctypes.windll.kernel32.CreateFileA("example.txt".encode("ascii"), GENERIC_ALL, 0, None, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, None)
address = ctypes.windll.kernel32.VirtualAllocEx(hProcess, None, ctypes.c_int(len(data)), ctypes.c_int(0x1000), ctypes.c_int(0x40))
address = ctypes.windll.kernel32.VirtualAllocEx(hProcess, None, ctypes.c_int(len(data)), ctypes.c_int(0x1000), ctypes.c_int(0x40))
ctypes.windll.kernel32.WriteProcessMemory(hProcess, address, data, ctypes.c_int(len(data)), None)
hProcess = ctypes.windll.kernel32.OpenProcess(ctypes.c_int(0x1F0FFF), False, ctypes.c_int(pid))
ctypes.windll.kernel32.Sleep(3000)
'''

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