from pprint import pprint
import yara
import sys
import subprocess

rules = yara.compile("packers.yar")
matches = rules.match("regular_exe.exe")

# #l = sorted([j for sub in [i.strings for i in matches] for j in sub], key= lambda tup: tup[0])
for i in matches:
    print(i)
    # if i.meta != {}:
    #     print(i.meta)
    # if i.strings:
    #     for j in i.strings:
    #         print(j)
    #     print()
    #     print()
    #     print()
