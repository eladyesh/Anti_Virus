from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QDialog, QPushButton


class MyDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.button = QPushButton("Close", self)
        self.button.clicked.connect(self.close)


class DialogThread(QThread):
    dialog_closed = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.dialog = MyDialog()

    def run(self):
        self.dialog.exec_()
        self.dialog_closed.emit()


def on_dialog_closed():
    print("Dialog closed")
    # Execute the rest of the code here


thread = DialogThread()
thread.dialog_closed.connect(on_dialog_closed)
thread.start()
