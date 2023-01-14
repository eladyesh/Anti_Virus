import re

string = "f.encrypt"
pattern = re.compile(r'(\w+)\.encrypt')
match = pattern.search(string)
if match:
    print("got here")