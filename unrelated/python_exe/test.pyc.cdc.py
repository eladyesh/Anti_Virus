
import ctypes
import os
import platform
import binascii
data = binascii.unhexlify('b80a000000c3')
GENERIC_ALL = 268435456
CREATE_NEW = 1
FILE_ATTRIBUTE_NORMAL = 128
ctypes.windll.kernel32.Sleep(3000)
file_handle = ctypes.windll.kernel32.CreateFileA('example.txt'.encode('ascii'), GENERIC_ALL, 0, None, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, None)
pid = os.getpid()
hProcess = ctypes.windll.kernel32.OpenProcess(ctypes.c_int(2035711), False, ctypes.c_int(pid))
address = ctypes.windll.kernel32.VirtualAllocEx(hProcess, None, ctypes.c_int(len(data)), ctypes.c_int(4096), ctypes.c_int(64))
ctypes.windll.kernel32.WriteProcessMemory(hProcess, address, data, ctypes.c_int(len(data)), None)
ctypes.windll.kernel32.CloseHandle(hProcess)
