import ctypes
import platform

GENERIC_ALL = 0x10000000
CREATE_NEW = 1
FILE_ATTRIBUTE_NORMAL = 0x80

ctypes.windll.kernel32.Sleep(2000)
file_handle = ctypes.windll.kernel32.CreateFileA("example.txt".encode("ascii"), GENERIC_ALL, 0, None, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, None)