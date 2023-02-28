import ctypes
import os
import sys
import threading
import time
import json
import pyuac
from pyuac import main_requires_admin
import requests
import argparse
import hashlib
import base64
import subprocess
import pydivert
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
import socket
import logging

# Configure the logger
logging.basicConfig(level=logging.INFO)

ip_for_server = socket.gethostbyname_ex(socket.gethostname())[-1][-1]


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<html>")
        self.wfile.write(b"<head><title>My Page</title></head>")
        self.wfile.write(b"<body>")
        self.wfile.write(b"<div style='text-align: center'>")
        self.wfile.write(b"<h1 style='margin-top: 70px;font-size:80px'>Hello User</h1>")
        for i in range(2):
            self.wfile.write(b"</br>")
        self.wfile.write(b"<p style='font-size: 60px;'>You have entered a website that was found suspicious by my "
                         b"AntiVirus</p>")
        self.wfile.write(b"</br>")
        self.wfile.write(b"<p style='font-size: 60px;'>You will now not be able to address this website</p>")
        self.wfile.write(b"</div>")
        self.wfile.write(b"</body>")
        self.wfile.write(b"</html>")


def start_server():
    httpd = HTTPServer((ip_for_server, 8080), RequestHandler)
    httpd.serve_forever()


@main_requires_admin
def main():

    # Define color codes
    BLUE = 9
    GREEN = 10
    YELLOW = 14
    RED = 12
    PURPLE = 13

    # Set console color
    os.system(f"color {RED:x}")

    block_ip = sys.argv[1:]
    # logging.info("NOW BLOCKING THE IP'S REPRESENTED ON THE SCREEN")
    print(f"\033[1;{RED}mNOW BLOCKING THE IP'S REPRESENTED ON THE SCREEN\033[0m")
    print("")

    server_thread = threading.Thread(target=start_server)
    server_thread.start()
    with pydivert.WinDivert() as w:
        for packet in w:
            if packet.dst_addr in block_ip:
                print("got here to block ip")
                ip = packet.dst_addr
                # print("packet dst in block ip ", packet.src_port, packet.dst_port, packet.src_addr, packet.dst_addr,packet.direction)
                # print(f"got here out {packet.is_outbound}")
                packet.dst_addr = ip_for_server
                packet.dst_port = 8080
                packet.direction = 0
                # print("packet modified ", packet.src_port, packet.dst_port, packet.src_addr, packet.dst_addr, packet.direction)
            if packet.src_addr == ip_for_server and packet.src_port == 8080:
                # print("packet src http ", packet.src_port, packet.dst_port, packet.src_addr, packet.dst_addr,
                #       packet.direction)
                packet.src_addr = ip
                packet.src_port = 80
                packet.direction = 1
                # print("packet modified ", packet.src_port, packet.dst_port, packet.src_addr, packet.dst_addr,
                #       packet.direction)
            w.send(packet)


if __name__ == "__main__":
    main()
