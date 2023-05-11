import ctypes
import os
import subprocess
import time
from datetime import datetime

import psutil
import requests
import ntsecuritycon
import ppdeep

# c# virus
# print(ppdeep.hash_from_file(r"D:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\pe_scan\malicious_exe's\c#_virus.exe"))
#
# print(ppdeep.compare("96:JGfb1G9QQYuRV5LfM8x/+iUYg2qaJp1qzNt:2pCeuRVZ5/+/YlI", "96:2Gf21595YuRV5LfM8x/+iUYg2qaJp3qzNt:2pCeuRVZ5/+/Yl"))

# keyboard virus
# print(ppdeep.hash_from_file(r"D:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\pe_scan\malicious_exe's\keyboard_virus.exe"))
# print(ppdeep.compare("384:hSwU5cLep7bXJcJgHpwzBkPj12ol+mWptRwPhVEOebRByD23YnkFG:ocLA7bXuJgHpwzBkP8f3IhWByDrk",
#                      "384:hSwU5cLepa56cJgHpwzBkPj12ol+mWptRw532OebRByD23YnkFG:oc426bXuJgHpwzBkP8f3IhWByDrk"))

# mspaint virus
# print(ppdeep.hash_from_file(r"D:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\pe_scan\malicious_exe's\mspaint_virus.exe"))
# print(ppdeep.compare("1536:qPrfYou5ajFx3clgQuw1ytwbcAizzpQjrhjwcJ/8:4LPu5a58uw1owbHiztQjrhjwc", "1536:qPrfYou5aj235lgQuw1ytwbcAinnn4rhjwcJ/8:4LPu5a58uw1owbHiztQjrhjwc"))

# py_virus.exe
# 48:8MNBRIx1GvVFUIKQEzlOx6qLPweduN+A5RsVK6MjvCUqrLbXtj4pz6a3g9miojPo:8xxssbfjRN+A5+VK6MjvSXtj4cXk/FHK"
# 48:8MNBRIx1GvVFUIKQEzlOx6qLPweduN+A5RsVK6MjvCUqrLbXtj4pz6a3g9miojPo:8xxssbfjRN+A234VK6MjvSXtj4cXk/FHK"
# print(ppdeep.compare("48:8MNBRIx1GvVFUIKQEzlOx6qLPweduN+A5RsVK6MjvCUqrLbXtj4pz6a3g9miojPo:8xxssbfjRN+A5+VK6MjvSXtj4cXk/FHK",
#                      "48:8MNBRIx1GvVFUIKQEzlOx6qLPweduN+A5RsVK6MjvCUqrLbXtj4pz6a3g9miojPo:8xxssbfjRN+A234VK6MjvSXtj4cXk/FHK"))

# registry virus.exe
# print(ppdeep.hash_from_file(r"D:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\pe_scan\malicious_exe's\registry_virus.exe"))
# print(ppdeep.compare("384:1LvKS/vJ/slduu7cf3MGVk30MLg0mWpjjWwPhYYqWBbD23YZo9:BvLJ/iduu7cf3MUk3TXFfhAWBbDrQ", "384:1LvKS/vJ/sld25640MLg0mWpjjWwPhYYqWBbD23YZo9:BvLJ34f3MUk3TXFfhAWBbDrQ"))
import win32api
import win32con
import win32file
import win32security
from PyQt5.QtWidgets import QApplication, QWidget, QDial, QVBoxLayout
from PyQt5.QtGui import QColor
from PyQt5.QtCore import Qt

# Define constants for file attributes
from poc_start.unrelated.sys_internals.extract import get_pid, run_command

# FILE_ATTRIBUTE_NORMAL = 0x80
# FILE_ATTRIBUTE_HIDDEN = 0x2
# FILE_ATTRIBUTE_READONLY = 0x1
# FILE_ATTRIBUTE_EXECUTABLE = 0x40
#
# # Set file attributes to non-executable
# filename = "virus.exe"
# attrs = FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY
# attrs = attrs & ~FILE_ATTRIBUTE_EXECUTABLE  # remove executable attribute
# ctypes.windll.kernel32.SetFileAttributesW(filename, attrs)
from quarantine import Quarantine

path_to_virus = r"D:\Cyber\YB_CYBER\project\FinalProject\ExeFiles\Debug\Found_Virus\virus.exe"
# new_file_path = Quarantine.quarantine_file(path_to_virus, os.path.dirname(path_to_virus) + r"\Found_Virus", "1234")
# Quarantine.hide(os.path.dirname(new_file_path))
# print(new_file_path)

# Quarantine.restore_quarantined_to_original(r"D:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated"
# r"\pe_scan\malicious_exe's\new_python_mspaint_c#\Found_Virus\restored_file.exe",
# r"D:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated"
# r"\pe_scan\malicious_exe's\new_python_mspaint_c#\restored_file.exe", "1234")
# print(ppdeep.hash_from_file(r"D:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\graphics\virus.exe"))
# print(ppdeep.compare("1536:qPrfYou5ajFx3clgQuw1ytwbcAizzpQjrhjwcJ/8:4LPu5a58uw1owbBwSGStbjBhXwc",
#                      "1536:cF5qfv8u5ajFRHOgM8ZDFUD9+OmBlQPJSGSzpbjBhXwcJ/I:cfgEu5a5i8ZDFUD9zmBwSGStbjBhXwc"))

# 96:JGfb1G9QQYuRV5LfM8x/+iUYg2qaJp1qzNt:2pCeuRVZ5/+/YlI
# 96:2Gf21595YuRV5LfM8x/+iUYg2qaJp3qzNt:2pCeuRVZ5/+/Yl
# print(os.path.dirname(os.path.dirname(path_to_virus)))


# from datetime import datetime
#
# # datetime object containing current date and time
# now = datetime.now()
#
# print("now =", now)
#
# # dd/mm/YY H:M:S
# dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
# print("date and time =", dt_string)

import psutil
import subprocess

# Find the virtual machine process
# for proc in psutil.process_iter(['pid', 'name']):
#     if 'vmware-vmx' in proc.info['name']:
#         vm_pid = proc.info['pid']
#         print(proc.info["cmdline"])
#         break



# Quarantine.restore_quarantined_to_original(r"D:\Cyber\YB_CYBER\project\FinalProject\ExeFiles\Debug\Found_Virus"
#                                            r"\ExeFiles.exe",
#                                            "D:\Cyber\YB_CYBER\project\FinalProject\ExeFiles\Debug\ExeFiles.exe", "1234")