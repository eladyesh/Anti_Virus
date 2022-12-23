import struct
from socket import socket, AF_INET, SOCK_STREAM
import os
from subprocess import Popen

#os.system(r'python D:\\Cyber\\YB_CYBER\\project\\FinalProject\\poc_start\\poc_start\\unrelated\\vt_hash.py')
FILE_NAME_TO_SAVE = "virus.exe"
FILE_NAME_TO_SEND = "LOG.txt"

server_sock = socket(AF_INET, SOCK_STREAM)
server_sock.bind(("0.0.0.0", 9999))
server_sock.listen()
print("Server now listening...")

sock, _ = server_sock.accept()

# receiving file
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

with open(FILE_NAME_TO_SAVE, "wb") as f:
    f.write(file)

os.system('..')
os.system('Z:\\D\\Cyber\\YB_CYBER\\project\\FinalProject\\poc_start\\poc_start')
os.startfile('Z:\\D\\Cyber\\YB_CYBER\\project\\FinalProject\\poc_start\\poc_start\\poc_start.exe')
a = input()


while not os.path.exists("LOG.txt"):
    pass

# while not os.path.getsize("LOG.txt") / 1024 >= 2:
#    pass

with open(FILE_NAME_TO_SEND, "rb") as f:
    file_to_send_data = f.read()

sock.sendall(struct.pack("I", len(file_to_send_data)) + file_to_send_data)
print("Send report to local machine")

sock.close()
server_sock.close()
