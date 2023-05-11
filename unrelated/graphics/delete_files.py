import os
import time

import psutil
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QApplication, QSplashScreen
from threading import Thread
from poc_start.unrelated.graphics.helpful_widgets import stop_timer


def delete_file(path):
    if path is not None:
        if os.path.exists(path):
            os.remove(path)


def find_file_by_key_word(dir_path, key_word):
    for filename in os.listdir(dir_path):
        full_path = os.path.join(dir_path, filename)
        if key_word in filename:
            return full_path


if __name__ == '__main__':

    app = QApplication([])

    # Create a splash screen
    splash_pix = QPixmap('images/remove_file.png')
    splash = QSplashScreen(splash_pix, Qt.WindowStaysOnTopHint)
    splash.show()

    terminated = False
    for process in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            process_info = process.as_dict(attrs=['pid', 'name', 'cmdline'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        else:
            process_name = process_info['name']
            process_cmdline = process_info['cmdline']
            print(process_name, process_info['cmdline'])
            if process_name == "python.exe" and not any("delete_files.py" in element for element in process_cmdline):
                process.kill()
                stop_timer(500)

                terminated = True
                break

    if terminated:

        time.sleep(0.5)

        # Create a splash screen
        splash_pix = QPixmap('images/remove_file.png')
        splash = QSplashScreen(splash_pix, Qt.WindowStaysOnTopHint)
        splash.show()

        while not app.closingDown():
            if splash.isVisible():
                break
            time.sleep(0.1)

    delete_file("virus.exe")
    # delete_file("Found_Virus")
    delete_file("LOG.txt")
    delete_file(os.path.abspath(os.path.join(os.getcwd(), "..", "..") + "\LOG.txt"))
    delete_file(os.path.abspath(os.path.join(os.getcwd(), "..", "..") + "\LOG_MEMORY.txt"))
    delete_file(os.path.abspath(os.path.join(os.getcwd(), "..") + "\sys_internals\output_handles.txt"))
    delete_file(find_file_by_key_word(os.getcwd(), ".pyc"))
    delete_file("log_python.txt")
    # delete_file(find_file_by_key_word(os.getcwd(), "output"))

    os.system("python pyqt_tests.py")
    # restart_vm()

    timer = QTimer()
    timer.timeout.connect(lambda: [app.exit(), splash.close(), timer.stop()])
    timer.start(2000)

    # Run the application event loop
    app.exec_()
