import sys, os
import threading
import time

from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import Qt, QUrl, QThreadPool, QRunnable, pyqtSlot, QObject, pyqtSignal
import PyQt5.QtGui
import shutil
from poc_start.send_to_vm.sender import Sender
from poc_start.unrelated.hash_scan.vt_hash import VTScan
import subprocess

PATH_TO_MOVE = r"D:\\Cyber\\YB_CYBER\\project\\FinalProject\\poc_start\\poc_start\\unrelated\\graphics"

qss = """
#Window{ 
    background-color: white 
}
QPushButton[flat="true"]{
    background-color: white;
    border: 0px;
    margin-top: 25px;
    margin-bottom: 5px;
    padding: 15px 32px;
}
QPushButton:hover {
    color: purple;
    font-size: 15px;
    border-bottom: 1px solid purple;
}
QLabel{
    margin-top: 25px;
    margin-bottom: 20px;
}
"""


def run_command(cmd):
    """
    runs cmd command in the command prompt and returns the output
    arg: cmd
    ret: the output of the command
    """
    return subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            shell=True,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE,
                            encoding="utf-8")


def activate_sender():
    print("got to sender")
    s = Sender()
    s.run()


class Worker(QRunnable):
    def __init__(self, fn, *args, **kwargs):
        super(Worker, self).__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    @pyqtSlot()
    def run(self):
        self.fn(*self.args, **self.kwargs)


class ListBoxWidget(QListWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        # perform drag and drop
        self.setAcceptDrops(True)
        self.setGeometry(0, 0, 500, 300)
        self.move(300, 150)
        # self.move(QApplication.desktop().screen().rect().center()- self.rect().center())
        # self.resize(300, 300)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.setDropAction(Qt.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            event.setDropAction(Qt.CopyAction)
            event.accept()
            links = []

            for url in event.mimeData().urls():
                if url.isLocalFile():  # checking if url
                    links.append(str(url.toLocalFile()))
                else:  # meaning --> a website or other url
                    links.append(str(url.toString()))

            self.addItems(links)

        else:
            event.ignore()


class AppDemo(QMainWindow):

    def __init__(self):
        super().__init__()

        pagelayout = QVBoxLayout()
        btn_layout = QHBoxLayout()
        activate_btn_layout = QHBoxLayout()
        self.resize(1200, 600)

        self.listbox_view = ListBoxWidget(self)
        self.btn = QPushButton('Get Value', self)
        self.start_vm_btn = QPushButton('Start Virtual Machine', self)
        activate_btn_layout.addWidget(self.start_vm_btn)
        activate_btn_layout.addWidget(self.btn)

        self.l1 = QLabel(self)
        self.l1.setText("My Anti Virus")
        self.l1.setFont(QFont('Arial', 14))
        self.l1.setAlignment(Qt.AlignCenter)

        self.dynamic_button = QPushButton("Dynamic Analysis")
        self.dynamic_button.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.dynamic_button.setFlat(True)

        self.static_button = QPushButton("Static Analysis")
        self.static_button.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.static_button.setFlat(True)

        self.hash_button = QPushButton("Hash Analysis")
        self.hash_button.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.hash_button.setFlat(True)

        # btn_layout.addItem(Qt.SpacerItem(0, 0,QSizePolicy.Expanding, Qt.QSizePolicy.Minimum))
        btn_layout.addStretch(1)
        btn_layout.addWidget(self.dynamic_button, Qt.AlignCenter)
        btn_layout.addWidget(self.static_button, Qt.AlignCenter)
        btn_layout.addWidget(self.hash_button, Qt.AlignCenter)
        btn_layout.setAlignment(Qt.AlignCenter)

        pagelayout.setAlignment(Qt.AlignCenter)
        pagelayout.addWidget(self.l1)
        pagelayout.addLayout(btn_layout)
        pagelayout.addWidget(self.listbox_view)
        pagelayout.addLayout(activate_btn_layout)
        pagelayout.addStretch(1)
        pagelayout.setContentsMargins(20, 20, 20, 20)

        widget = QWidget()
        widget.setLayout(pagelayout)
        self.setCentralWidget(widget)

        self.btn.clicked.connect(lambda: self.getSelectedItem())
        self.start_vm_btn.clicked.connect(lambda: self.start_vm())

    def getSelectedItem(self):
        print("got here")
        item = QListWidgetItem(self.listbox_view.item(0))
        path = item.text()
        bytes = b""

        with open(path, "rb") as f:
            bytes += f.read()
        shutil.move(str(path), PATH_TO_MOVE + "\\virus.exe")
        with open(path, "wb") as f:
            f.write(bytes)

        while not os.path.exists(r"D:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\graphics"
                                 r"\virus.exe"):
            print('File does not exists')
            pass

        self.threadpool_sender = QThreadPool()
        worker = Worker(activate_sender)
        self.threadpool_sender.start(activate_sender)

    def activate_vm(self):
        os.chdir(r"C:\Program Files (x86)\VMware\VMware Workstation")
        os.system(r'vmrun -T ws start "C:\\Users\\user\\OneDrive\\Windows 10 and later x64.vmx"')

    def start_vm(self):
        self.threadpool_vm = QThreadPool()
        worker = Worker(self.activate_vm)
        self.threadpool_vm.start(self.activate_vm)


app = QApplication(sys.argv)
app.setStyleSheet(qss)
demo = AppDemo()
demo.show()

sys.exit(app.exec())
