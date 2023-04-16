import os
import struct
from socket import socket, AF_INET, SOCK_STREAM
import os.path

FILE_NAME_TO_SEND = r"E:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\graphics\virus.exe"
FILE_NAME_TO_SAVE = r"E:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\graphics\LOG.txt"

#
# sock = socket(AF_INET, SOCK_STREAM)
# sock.connect(("192.168.1.28", 9999))
#
# # sending file
# with open(FILE_NAME_TO_SEND, "rb") as f:
#     file_to_send_data = f.read()
#
# sock.sendall(struct.pack("I", len(file_to_send_data)) + file_to_send_data)
#
# # receiving file
# file_to_recv_size = struct.unpack("I", sock.recv(struct.calcsize("I")))[0]
# file = b''
# while len(file) < file_to_recv_size:
#     try:
#         file_fragment = sock.recv(file_to_recv_size - len(file))
#     except:
#         print("error in recv")
#         quit()
#     if not file_fragment:
#         print("error in data")
#         quit()
#     file = file + file_fragment
#
# with open(FILE_NAME_TO_SAVE, "wb") as f:
#     f.write(file)
#     print("received report from virtual machine")
#
# sock.close()


class Sender:

    def __init__(self):

        print("Starting Sender")
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.sock.connect(("172.16.118.137", 9999)) # 172.16.4.73
        print("Connected to Virtual Machine")

    def run(self):

        print("Sending file")
        with open(FILE_NAME_TO_SEND, "rb") as f:
            file_to_send_data = f.read()

        self.sock.sendall(struct.pack("I", len(file_to_send_data)) + file_to_send_data)

        # receiving file
        file_to_recv_size = struct.unpack("I", self.sock.recv(struct.calcsize("I")))[0]
        file = b''
        while len(file) < file_to_recv_size:
            try:
                file_fragment = self.sock.recv(file_to_recv_size - len(file))
            except:
                print("error in recv")
                quit()
            if not file_fragment:
                print("error in data")
                quit()
            file = file + file_fragment

        with open(FILE_NAME_TO_SAVE, "wb") as f:
            f.write(file)
            print("received report from virtual machine")
            yield 1

        self.sock.close()


if __name__ == "__main__":
    s = Sender()
    s.run()
