import ctypes
import os
import platform
import binascii

data = binascii.unhexlify("b80a000000c3")

GENERIC_ALL = 0x10000000
CREATE_NEW = 1
FILE_ATTRIBUTE_NORMAL = 0x80

ctypes.windll.kernel32.Sleep(3000)
file_handle = ctypes.windll.kernel32.CreateFileA("example.txt".encode("ascii"), GENERIC_ALL, 0, None, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, None)

# Open a handle to the process
pid = os.getpid()
hProcess = ctypes.windll.kernel32.OpenProcess(ctypes.c_int(0x1F0FFF), False, ctypes.c_int(pid))

# Allocate memory in the process for the data to be written
address = ctypes.windll.kernel32.VirtualAllocEx(hProcess, None, ctypes.c_int(len(data)), ctypes.c_int(0x1000), ctypes.c_int(0x40))

# Write the data to the memory address
ctypes.windll.kernel32.WriteProcessMemory(hProcess, address, data, ctypes.c_int(len(data)), None)

# Close the handle to the process
ctypes.windll.kernel32.CloseHandle(hProcess)