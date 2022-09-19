from winreg import *
from contextlib import suppress
import itertools


# # # Open registry key of choice
# my_key = OpenKey(HKEY_LOCAL_MACHINE, "Software\\7-Zip", 0, KEY_SET_VALUE)
# print(my_key)
#
# # Get a key value
# my_key_val = QueryValueEx(my_key, 'Path')
#
# # Close registry key
# my_key.Close()

# def read_key(path):
#
#     try:
#         key_dict = {}
#         count = 0
#         key = OpenKey(HKEY_LOCAL_MACHINE, f"{path}", 0, KEY_ALL_ACCESS)
#         while 1:
#             name, value, type = EnumValue(key, count)
#             key_dict[name] = value
#             count = count + 1
#     except WindowsError:
#         pass
#
#     return key_dict
#
#
# m = OpenKey(HKEY_CURRENT_USER, "SOFTWARE")
# a = EnumKey(m, 0)
# for key,value in read_key("SOFTWARE" + "\\" + a).items():
#     print(key, value)

