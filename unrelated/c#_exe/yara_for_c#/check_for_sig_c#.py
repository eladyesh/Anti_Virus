import yara
import os

rule = yara.compile("open_for_c#.yar")
matches = rule.match(r"example_for_yara.exe")
for match in matches:
    if match.rule == "txt_file_name_in_exe":
        decoded_text = match.strings[0][2].decode('utf-16le')
        print(decoded_text)
        continue
    print(match.strings)