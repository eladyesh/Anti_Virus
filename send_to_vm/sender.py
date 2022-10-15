import struct
from socket import socket, AF_INET, SOCK_STREAM

FILE_NAME_TO_SEND = "virus.exe"
FILE_NAME_TO_SAVE = "LOG.txt"

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
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.sock.connect(("192.168.1.28", 9999))

    def run(self):

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

        self.sock.close()


if __name__ == "__main__":
    s = Sender()
    s.run()
