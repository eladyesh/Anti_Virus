import re

# port scan
# Use regular expression to match the function names, parameters, and result
calls = "s.value = winsock.socket(2, 1, 6)\nresult = winsock.connect(s, address, ctypes.sizeof(address), port)\nwinsock.closesocket(s)\nwinsock.getaddrinfo(target, None, None, ctypes.byref(address))"
pattern = re.compile(r"(\w+)\s*=\s*winsock\.(\w+)\((.*)\)|winsock\.(\w+)\((.*)\)")

functions_dict = {}

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
