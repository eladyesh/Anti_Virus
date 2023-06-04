import struct
from socket import socket, AF_INET, SOCK_STREAM
import os
from subprocess import Popen
import psutil
from unrelated.sys_internals.extract import SysInternals

#os.system(r'python D:\\Cyber\\YB_CYBER\\project\\FinalProject\\poc_start\\poc_start\\unrelated\\vt_hash.py')

# Constants
FILE_NAME_TO_SAVE = "virus.exe"
FILE_NAME_TO_SEND = "LOG.txt"

# Opening socket
server_sock = socket(AF_INET, SOCK_STREAM)
server_sock.bind(("0.0.0.0", 9999))
server_sock.listen()
print("Server now listening...")

# Accepting connection
sock, _ = server_sock.accept()

# Receiving file
file_to_recv_size = struct.unpack("I", sock.recv(struct.calcsize("I")))[0]
file = b''
while len(file) < file_to_recv_size:
    try:
        file_fragment = sock.recv(file_to_recv_size - len(file))
    except:
        print("error in recv")
        quit()
    if not file_fragment:
        print("error in data")
        quit()
    file = file + file_fragment

# Saving received file
with open(FILE_NAME_TO_SAVE, "wb") as f:
    f.write(file)

# Running necessary commands
os.system('..')
os.system('Z:\\E\\Cyber\\YB_CYBER\\project\\FinalProject\\poc_start\\poc_start')
os.startfile('Z:\\E\\Cyber\\YB_CYBER\\project\\FinalProject\\poc_start\\poc_start\\poc_start.exe')
# a = input()

# Waiting for processes to finish
while "poc_start.exe" in [p.name() for p in psutil.process_iter()]:
    pass
while "virus.exe" in [p.name() for p in psutil.process_iter()]:
    pass

# Appending LOG_MEMORY.txt contents to LOG.txt
while not os.path.exists("LOG.txt") and not os.path.exists("LOG_MEMORY.txt"):
    pass

# Sending file to the local machine
with open('LOG_MEMORY.txt', 'r') as file1, open('LOG.txt', 'a') as file2:
    file2.write(file1.read())

# while not os.path.getsize("LOG.txt") / 1024 >= 2:
#    pass

# Running handle.exe on the file
with open(FILE_NAME_TO_SEND, "rb") as f:
    file_to_send_data = f.read()

sock.sendall(struct.pack("I", len(file_to_send_data)) + file_to_send_data)
print("Send report to local machine")

# Run handle.exe on the file
s = SysInternals()
s.run_handle()

# Closing socket and server socket
sock.close()
server_sock.close()
