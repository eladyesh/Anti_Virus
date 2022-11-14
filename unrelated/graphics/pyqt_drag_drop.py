import sys, os
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import Qt, QUrl
import PyQt5.QtGui
import shutil
from poc_start.send_to_vm.sender import Sender
from poc_start.unrelated.hash_scan.vt_hash import VTScan


PATH_TO_MOVE = r"E:\\Cyber\\YB_CYBER\\project\\FinalProject\\poc_start\\poc_start\\unrelated\\graphics"

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
        self.resize(1200, 600)

        self.listbox_view = ListBoxWidget(self)
        self.btn = QPushButton('Get Value', self)

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

        #btn_layout.addItem(Qt.SpacerItem(0, 0,QSizePolicy.Expanding, Qt.QSizePolicy.Minimum))
        btn_layout.addStretch(1)
        btn_layout.addWidget(self.dynamic_button, Qt.AlignCenter)
        btn_layout.addWidget(self.static_button, Qt.AlignCenter)
        btn_layout.addWidget(self.hash_button, Qt.AlignCenter)
        btn_layout.setAlignment(Qt.AlignCenter)

        pagelayout.setAlignment(Qt.AlignCenter)
        pagelayout.addWidget(self.l1)
        pagelayout.addLayout(btn_layout)
        pagelayout.addWidget(self.listbox_view)
        pagelayout.addWidget(self.btn)
        pagelayout.addStretch(1)
        pagelayout.setContentsMargins(20, 20, 20, 20)

        widget = QWidget()
        widget.setLayout(pagelayout)
        self.setCentralWidget(widget)

        self.btn.clicked.connect(lambda: self.getSelectedItem())

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

        s = Sender()
        s.run()


app = QApplication(sys.argv)
app.setStyleSheet(qss)
demo = AppDemo()
demo.show()

sys.exit(app.exec())