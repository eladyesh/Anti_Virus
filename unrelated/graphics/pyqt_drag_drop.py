import sys, os
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import Qt, QUrl
import PyQt5.QtGui
import shutil
import os
from send_to_vm.sender import Sender
from unrelated.hash_scan.vt_hash import VTScan

PATH_TO_MOVE = r"D:\\Cyber\\YB_CYBER\\project\\FinalProject\\poc_start\\poc_start"  # TODO change path


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

        self.resize(1200, 600)
        self.listbox_view = ListBoxWidget(self)

        self.btn = QPushButton('Get Value', self)
        self.btn.setGeometry(850, 400, 200, 50)  # x, y, width, height

        self.l1 = QLabel(self)
        self.l1.move(50, 50)
        self.l1.setText("My Anti Virus")
        self.l1.setGeometry(500, 0, 200, 200)
        self.l1.setFont(QFont('Arial', 14))

        self.btn.clicked.connect(lambda: self.getSelectedItem())

    def getSelectedItem(self):
        item = QListWidgetItem(self.listbox_view.currentItem())
        path = item.text()
        shutil.move(str(path), PATH_TO_MOVE + "\\virus.exe")

        s = Sender()
        s.run()


app = QApplication(sys.argv)

demo = AppDemo()
demo.show()

sys.exit(app.exec())
