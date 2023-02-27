import ctypes
import os
import sys
from pydivert import WinDivert
import pyuac
from pyuac import main_requires_admin
import socket
import pydivert
import time


@main_requires_admin
def main():

    blocks = []
    print("got here - now running in admin")

    # the rest of the code will run as administrator
    with WinDivert("inbound and ip.DstAddr == 192.168.1.100") as w:
        for packet in w:
            print("packet.dropping...")
            if packet in blocks:
                packet.drop()

main()
