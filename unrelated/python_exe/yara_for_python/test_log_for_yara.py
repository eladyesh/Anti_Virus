import yara
import os

# Compile the YARA rule
rule = yara.compile(source="""
rule detect_with_open_call
{
    strings:
        $with_open_call = "with open("
        $filename = /with open\("([^"]+)",/
        $mode = /with open\("[^"]+", "([^"]+)"\)/

    condition:
        $with_open_call and $filename and $mode
}
""")

# Define the Python code to scan
code = '''
with open("hello.txt", "w") as f:
    f.write("hello world1")
'''

# Run the YARA rule against the Python code
matches = rule.match(data=code)

# Output the matches
if matches:
    print("Match found:")
    for match in matches:
        print(match.strings)
else:
    print("No matches found.")