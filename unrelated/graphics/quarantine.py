import base64
import hashlib
import os
import shutil
import sys
import time
import psutil
import win32api
import win32con
import win32file
import win32security
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QSplashScreen, QApplication
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import ctypes
import ntsecuritycon as con
import stat
from datetime import datetime

from pyuac import main_requires_admin

FILE_ATTRIBUTE_HIDDEN = 0x02

def md5(path):
    hash_md5 = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

class Quarantine:

    @staticmethod
    def hide(path):
        if not os.path.exists(path):
            os.makedirs(path)
        ret = ctypes.windll.kernel32.SetFileAttributesW(path, FILE_ATTRIBUTE_HIDDEN)

    @staticmethod
    def create_dir(path):
        try:
            os.makedirs(path)
            print(f"Directory created at path: {path}")
        except FileExistsError:
            print(f"Directory already exists at path: {path}")
        except Exception as e:
            print(f"Failed to create directory at path: {path}\nError: {str(e)}")

    @staticmethod
    def derive_key(password, salt):

        """Derive a 32-byte key from the password and salt using PBKDF2."""
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt_file(file_path, password):
        with open(file_path, "rb") as f:
            data = f.read()

        # Derive a key from the password using PBKDF2
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
        key = kdf.derive(password.encode())

        # Pad the key to the required length
        fernet_key = Fernet(base64.urlsafe_b64encode(key[:32]))

        # Encrypt the data with the key
        encrypted_data = fernet_key.encrypt(data)

        # Write the salt and the encrypted data to the file
        with open(file_path, "wb") as f:
            f.write(salt)
            f.write(encrypted_data)

    @staticmethod
    def decrypt_file(file_path, password):
        with open(file_path, "rb") as f:
            salt = f.read(16)
            encrypted_data = f.read()

        # Derive a key from the password using PBKDF2
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
        key = kdf.derive(password.encode())

        # Pad the key to the required length
        fernet_key = Fernet(base64.urlsafe_b64encode(key[:32]))

        # Decrypt the data with the key
        decrypted_data = fernet_key.decrypt(encrypted_data)

        # Write the decrypted data to the file
        with open(file_path, "wb") as f:
            f.write(decrypted_data)

    @staticmethod
    def quarantine_file(file_path, quarantine_folder, password):
        """Quarantine the file at the given path in the given quarantine folder and encrypt it with the given
        password. """

        md5_hash = md5(file_path)

        # Get the current user's SID
        user = win32api.GetUserName()
        domain = win32api.GetComputerName()
        sid, domain, type = win32security.LookupAccountName("", user)

        # create a new ACE
        ace = win32security.ACL()
        ace.AddAccessAllowedAce(win32security.ACL_REVISION, win32file.FILE_GENERIC_READ, sid)

        # create a new security descriptor with the ACE
        sd = win32security.SECURITY_DESCRIPTOR()
        sd.SetSecurityDescriptorDacl(1, ace, 0)

        if not os.path.exists(quarantine_folder):
            os.makedirs(quarantine_folder)

            # Set the permissions on the quarantine folder to read and execute only for the owner
            os.chmod(quarantine_folder, 0o500)

        # Get the file name
        file_name = os.path.basename(file_path)

        # Construct the new file path in the quarantine folder
        new_file_path = os.path.join(quarantine_folder, file_name)

        # Move the file to the quarantine folder
        shutil.move(file_path, new_file_path)

        # Encrypt the file with the password
        Quarantine.encrypt_file(new_file_path, password)

        # Set the permissions on the file to read-only for the owner
        os.chmod(new_file_path, 0o400)

        filename = "quarantine_data.txt"
        mode = "a" if os.path.exists(
            filename) else "w"  # Open in "append" mode if file exists, otherwise "write" mode to create a new file
        with open(filename, mode) as f:
            f.write(f"\n{md5_hash}|{file_path}|{os.path.basename(file_path)}|{datetime.now().strftime(r'%d/%m/%Y %H:%M:%S')}")

        return new_file_path

    @staticmethod
    def restore_quarantined_to_original(file_path, original_path, password):

        # Construct the original file path outside the quarantine folder
        original_file_path = original_path

        # Set the permissions on the file to read, write, and execute for the owner
        os.chmod(file_path, 0o700)

        # Decrypt the file with the password
        Quarantine.decrypt_file(file_path, password)

        # Move the decrypted file to the original file path
        shutil.move(file_path, original_file_path)

        os.chmod(os.path.dirname(file_path), 0o700)
        # os.remove(os.path.dirname(file_path))
        shutil.rmtree(os.path.dirname(file_path))

        print(f"{file_path} has been restored to {original_file_path}")

    @staticmethod
    def restore_file(file_path, quarantine_folder, password):

        # Get the file name
        file_name = os.path.basename(file_path)

        # Construct the original file path outside the quarantine folder
        original_file_path = os.path.join(os.path.dirname(quarantine_folder), file_name)
        # original_file_path = os.path.join(os.path.dirname(quarantine_folder), file_name) # add another param -->
        # the real file path, and change the original_file_path to it

        # Set the permissions on the file to read, write, and execute for the owner
        os.chmod(file_path, 0o700)

        # Decrypt the file with the password
        Quarantine.decrypt_file(file_path, password)

        # Move the decrypted file to the original file path
        shutil.move(file_path, original_file_path)

        os.chmod(os.path.dirname(file_path), 0o700)
        # os.remove(os.path.dirname(file_path))
        shutil.rmtree(os.path.dirname(file_path))

        print(f"{file_path} has been restored to {original_file_path}")


if __name__ == "__main__":

    app = QApplication([])

    # Create a splash screen
    splash_pix = QPixmap('images/vaulting.gif')
    splash = QSplashScreen(splash_pix, Qt.WindowStaysOnTopHint)
    splash.show()

    # path = sys.argv[1:][0]
    for process in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            process_info = process.as_dict(attrs=['pid', 'name', 'cmdline'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        else:
            process_name = process_info['name']
            process_cmdline = process_info['cmdline']
            if process_name == "python.exe" and "quarantine.py" not in process_cmdline:
                process.terminate()
                break

    if not os.path.exists("Found_Virus"):
        # new_file_path = Quarantine.quarantine_file("virus.exe", "Found_Virus", "1234")
        new_file_path = Quarantine.quarantine_file("virus.exe", "Found_Virus", "1234")
        Quarantine.hide("Found_Virus")

    if os.path.exists("virus.exe"):
        os.remove("virus.exe")

    # Launch the new PyQt process
    os.system("python pyqt_tests.py")

    # Hide the splash screen after a short delay
    timer = QTimer()
    timer.timeout.connect(lambda: [app.exit(), splash.close(), timer.stop()])
    timer.start(2000)

    # Run the application event loop
    app.exec_()

    # Quarantine.restore_file("Found_Virus/virus.exe", "Found_virus", "1234")
