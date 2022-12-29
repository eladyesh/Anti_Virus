from multiprocessing import Queue, Process
from threading import Thread
import ppdeep
import concurrent.futures
import itertools

h1 = ppdeep.hash_from_file(r"D:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\hash_scan\virus.exe")
h2 = ppdeep.hash_from_file(r"D:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\de_bug\known_virus.exe")

print(h1)
print(h2)
print(ppdeep.compare(h1, h2))