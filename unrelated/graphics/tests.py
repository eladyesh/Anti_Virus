import os
import shutil
import subprocess

#subprocess.run(['D:\\Cyber\\YB_CYBER\\project\\FinalProject\\poc_start\\poc_start\\poc_start.exe'], shell=True, check=True)
# launch poc_start.exe and wait for it to finish

source_path = r"D:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\pe_scan\malicious_exe's\c#_virus.exe"

shutil.copy(source_path, os.getcwd() + "/virus.exe")