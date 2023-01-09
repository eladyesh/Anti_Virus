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
            if func_name == "open":

                # The first argument of the open function is the file name
                file_name = node.args[0]
                print(f"File name: {file_name.s}")

                # The second argument of the open function is the mode
                mode = node.args[1]
                print(f"Mode: {mode.s}")

                # Find the write function after the open function
                for next_node in ast.iter_child_nodes(node):
                    if isinstance(next_node, ast.Expr) and isinstance(next_node.value,
                                                                      ast.Call) and next_node.value.func.id == "write":
                        # The argument of the write function is the content to be written
                        content = next_node.value.args[0]
                        print(f"Content: {content.s}")

            elif func_name == "write":
                print("got here")


        #elif isinstance(node.func, ast.Attribute):
        #    print("got here 2")
        #    func_name = node.func.attr
        #    if func_name == "open":

        #        # The first argument of the open function is the file name
        #        file_name = node.args[0]
        #        print(f"File name: {file_name.s}")

        #        # The second argument of the open function is the mode
        #        mode = node.args[1]
        #        print(f"Mode: {mode.s}")

        #        # Find the write function after the open function
        #        for next_node in ast.iter_child_nodes(node):
        #            if isinstance(next_node, ast.Expr) and isinstance(next_node.value,
        #                                                              ast.Call) and next_node.value.func.id == "write":
        #                # The argument of the write function is the content to be written
        #                content = next_node.value.args[0]
        #                print(f"Content: {content.s}")
