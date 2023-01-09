import ast
import inspect

# Load the source code of the Python file
with open("to_inspect_file.py", "r") as f:
    source = f.read()

# Parse the source code
tree = ast.parse(source)

# Find the Call node that represents the open function
for node in ast.walk(tree):

    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            # func_name = node.func.attr
            func_name = f"{node.func.value.id}.{node.func.attr}"

        # Extract the arguments passed to the function
        args = [arg.id if isinstance(arg, ast.Name) else arg.s if isinstance(arg, ast.Str) else None for arg in node.args]

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