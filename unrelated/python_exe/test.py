import ctypes
from ctypes import wintypes as w

INVALID_HANDLE_VALUE = w.HANDLE(-1).value
GENERIC_ALL = 0x10000000
OPEN_ALWAYS = 4
FILE_ATTRIBUTE_NORMAL = 0x80

ctypes.windll.kernel32.Sleep(2000)
file_handler = ctypes.windll.kernel32.CreateFileA("elad.txt", GENERIC_ALL, 0, None, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, None)