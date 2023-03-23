import sys

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QIcon
from PyQt5.QtWidgets import QApplication, QDialog, QVBoxLayout, QLabel, QPushButton

if __name__ == '__main__':
    app = QApplication(sys.argv)

    message_box = MessageBox('Warning', 'This is a warning message!', 'warning')
    message_box.exec()

    message_box = MessageBox('Info', 'This is an info message!', 'info')
    message_box.exec()
