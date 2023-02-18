import yara
import os

rule = yara.compile("open_for_c#.yar")
matches = rule.match(r"example_for_yara.exe")
print(matches)
for match in matches:
    print(match.strings)

# import yara
#
# # Define Yara rules
# rules = '''
# import "pe"
#
# rule open_for_c
# {
#     strings:
#         $filename = /MyTest\.txt/
#         $open_call = /(File\.Open(Read|Write|)|new FileStream)\(\s*[^)]*\)/
#         $write_call = /(File\.Write|fs\.Write)\(/
#
#     condition:
#         any of ($*)
# }
# '''
#
# # Compile rules
# compiled_rules = yara.compile(source=rules)
#
# # Define source code
# source_code = '''
# File.Open("MyTest.txt", FileMode.Create);
# new FileStream("MyTest.txt", FileMode.Create);
# File.OpenText("MyTest.txt");
# File.WriteAllText("MyTest.txt", "some text");
# fs.Write(buffer, 0, buffer.Length);
# File.WriteAllBytes("MyTest.txt", buffer);
# '''
#
# # Match the rules against the source code
# matches = compiled_rules.match(data=source_code)
#
# # Print the matches
# if matches:
#     print("Matches found:")
#     for match in matches:
#         print(f"Rule: {match.rule} - Strings: {match.strings}")
# else:
#     print("No matches found.")