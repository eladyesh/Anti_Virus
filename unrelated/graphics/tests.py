import os
import subprocess

#subprocess.run(['D:\\Cyber\\YB_CYBER\\project\\FinalProject\\poc_start\\poc_start\\poc_start.exe'], shell=True, check=True)
# launch poc_start.exe and wait for it to finish
import time
os.startfile('D:\\Cyber\\YB_CYBER\\project\\FinalProject\\poc_start\\poc_start\\poc_start.exe')
while True:
    if not any(p.name() == 'poc_start.exe' for p in psutil.process_iter()):
        break
    time.sleep(1)
print('rest of code')
