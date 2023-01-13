import re

string = "anyvariable.starttls"
pattern = re.compile(r'(\w+)\.(\w+)')
match = pattern.search(string)
if match:
    variable = match.group(1)
    function = match.group(2)
    print("variable:", variable)
    print("function:", function)