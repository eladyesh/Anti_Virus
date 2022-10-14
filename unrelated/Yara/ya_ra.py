from pprint import pprint
import yara

rules = yara.compile("check.yar")
matches = rules.match("file_transfer\\virus.exe")
print(matches[0].strings)