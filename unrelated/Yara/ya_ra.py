from pprint import pprint
import yara
import numpy as np

rules = yara.compile("check.yar")
matches = rules.match("virus.exe")

#l = sorted([j for sub in [i.strings for i in matches] for j in sub], key= lambda tup: tup[0])
for i in matches:
    for j in i.strings:
        print(j)
    print()
    print()
    print()