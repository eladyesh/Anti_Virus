# calls = '''
# file_handle = ctypes.windll.kernel32.CreateFileA("example.txt".encode("ascii"), GENERIC_ALL, 0, None, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, None)
# address = ctypes.windll.kernel32.VirtualAllocEx(hProcess, None, ctypes.c_int(len(data)), ctypes.c_int(0x1000), ctypes.c_int(0x40))
# address = ctypes.windll.kernel32.VirtualAllocEx(hProcess, None, ctypes.c_int(len(data)), ctypes.c_int(0x1000), ctypes.c_int(0x40))
# ctypes.windll.kernel32.WriteProcessMemory(hProcess, address, data, ctypes.c_int(len(data)), None)
# hProcess = ctypes.windll.kernel32.OpenProcess(ctypes.c_int(0x1F0FFF), False, ctypes.c_int(pid))
# ctypes.windll.kernel32.Sleep(3000)
# '''

import requests
from bs4 import BeautifulSoup

def get_winapi_info(func_name: str) -> str:
    url = f"https://docs.microsoft.com/en-us/windows/win32/api/{func_name.lower()}"
    page = requests.get(url)
    soup = BeautifulSoup(page.content, 'html.parser')
    soup_str = soup.prettify()
    content_start = soup_str.find("<content>")
    content_end = soup_str.find("</content>")
    content_str = soup_str[content_start:content_end]
    p_start = content_str.find("<p>")
    p_end = content_str.find("</p>")
    p_tag = content_str[p_start:p_end + 4]
    p_text = p_tag.strip().replace("<p>", "").split(".")[0]
    return p_text.strip()


print(get_winapi_info("CreateFileA"))

