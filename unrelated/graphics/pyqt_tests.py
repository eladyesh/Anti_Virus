import sys, os
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5 import QtCore
from PyQt5.QtCore import Qt, QUrl, pyqtSlot, QRunnable, QThreadPool
import PyQt5.QtGui
from PyQt5.QtCore import QObject, QThread, pyqtSignal
import shutil
from poc_start.send_to_vm.sender import Sender
from poc_start.unrelated.hash_scan.vt_hash import VTScan
from poc_start.unrelated.pe_scan.entropy import *
from poc_start.unrelated.pe_scan.pe_tests import *
from poc_start.unrelated.Yara.ya_ra import YaraChecks
from poc_start.unrelated.fuzzy_hashing.ssdeep_check import *
from threading import Thread
from multiprocessing import Process
from http.server import HTTPServer, BaseHTTPRequestHandler

PATH_TO_MOVE = r"E:\\Cyber\\YB_CYBER\\project\\FinalProject\\poc_start\\poc_start\\unrelated\\graphics"

qss = """
#Window{ 
    background-color: white 
}
QMainWindow {
    background: linear-gradient(to right, #fff, #f5f5f5);
    border-radius: 10px;
    box-shadow: 10px 10px 5px #333;
    font-family: "Courier New", monospace;
    font-size: 16px;
    color: #333;
}
QPushButton[flat="true"]{
    background-color: white;
    border: 0px;
    margin-top: 25px;
    margin-bottom: 5px;
    padding: 15px 32px;
    font-size:20px;
    display:inline-block;
    min-width: 50px;
    min-height: 50px;
    max-width: 500px;
    max-height: 50px;
}
QPushButton:hover {
    color: purple;
    font-size: 20px;
    border-bottom: 1px solid purple;
}
QLabel{
    margin-top: 25px;
    margin-bottom: 20px;
    display:inline-block; 
    position: fixed;
}
"""


def make_label(text):
    label = QLabel(text)

    # Set the font to a decorative font
    font = QFont('Zapfino', 24)
    label.setFont(font)

    # Set the text color to purple
    palette = QPalette()
    palette.setColor(QPalette.Foreground, QColor(128, 0, 128))
    label.setPalette(palette)

    # Add a shadow effect to the text
    shadow = QGraphicsDropShadowEffect()
    shadow.setBlurRadius(5)
    shadow.setOffset(3, 3)
    label.setGraphicsEffect(shadow)

    return label


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

        self.page_layout = QVBoxLayout()
        self.btn_layout = QHBoxLayout()
        self.run_once = 0
        self.activate_btn_layout = QHBoxLayout()
        self.resize(1200, 600)

        self.listbox_view = ListBoxWidget(self)
        self.btn = QPushButton('Start Dynamic Scan', self)
        self.btn.setStyleSheet("QPushButton {background-color: #E6E6FA; color: #000080; border: 2px solid #9400D3; "
                               "border-radius: 10px; font: bold 14px; min-width: 80px; padding: 6px;} "
                               "QPushButton:hover {background-color: #D8BFD8; color: #4B0082;} QPushButton:pressed {"
                               "background-color: #DDA0DD; color: #8B008B;}")

        self.start_vm_btn = QPushButton('Start Virtual Machine', self)
        self.start_vm_btn.setStyleSheet(
            "QPushButton {background-color: #E6E6FA; color: #000080; border: 2px solid #9400D3; "
            "border-radius: 10px; font: bold 14px; min-width: 80px; padding: 6px;} "
            "QPushButton:hover {background-color: #D8BFD8; color: #4B0082;} QPushButton:pressed {"
            "background-color: #DDA0DD; color: #8B008B;}")

        self.activate_btn_layout.addWidget(self.start_vm_btn)
        self.activate_btn_layout.addWidget(self.btn)

        self.l1 = make_label("YeshScanner")
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
        # self.btn_layout.addStretch(1)
        self.btn_layout.addWidget(self.dynamic_button, Qt.AlignCenter)
        self.btn_layout.addWidget(self.static_button, Qt.AlignCenter)
        self.btn_layout.addWidget(self.hash_button, Qt.AlignCenter)
        self.btn_layout.setAlignment(Qt.AlignCenter)

        self.page_layout.setAlignment(Qt.AlignCenter)
        self.page_layout.addWidget(self.l1)
        self.page_layout.addLayout(self.btn_layout)
        self.page_layout.addWidget(self.listbox_view)
        self.page_layout.addLayout(self.activate_btn_layout)
        self.page_layout.addStretch(1)
        self.page_layout.setContentsMargins(20, 20, 20, 20)

        self.dynamic_visited = False
        self.static_visited = False
        self.hash_visited = False

        self.scroll = QScrollArea()  # Scroll Area which contains the widgets, set as the centralWidget
        self.widget = QWidget()  # Widget that contains the collection of Vertical Box

        self.widget.setLayout(self.page_layout)

        # Scroll Area Properties
        self.scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.scroll.setWidgetResizable(True)
        self.scroll.setWidget(self.widget)

        self.setCentralWidget(self.scroll)

        # frame = QFrame()
        # frame.setLayout(self.page_layout)
        #
        # # Create a scroll area and set the frame as its widget
        # scroll_area = QScrollArea()
        # scroll_area.setWidget(frame)
        # scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        #
        # # Set the scroll area as the central widget of the main window
        # self.setCentralWidget(scroll_area)

        self.btn.clicked.connect(lambda: self.getSelectedItem())
        self.start_vm_btn.clicked.connect(lambda: self.activate_vm())
        self.static_button.clicked.connect(lambda: [self.static_analysis()])
        self.hash_button.clicked.connect(lambda: [self.hash_analysis()])

    def clearLayout(self):

        if self.run_once == 0:
            for cnt in reversed(range(self.page_layout.count())):
                if cnt == 0 or cnt == 1:
                    continue
                widget = self.page_layout.takeAt(cnt).widget()
                if widget is not None:
                    widget.deleteLater()

            index = self.page_layout.indexOf(self.activate_btn_layout)
            self.page_layout.removeItem(self.page_layout.takeAt(index))
            self.activate_btn_layout.deleteLater()
            self.start_vm_btn.deleteLater()
            self.btn.deleteLater()
            self.run_once = 1

        if self.static_visited:
            self.index_table = self.page_layout.indexOf(self.table_and_strings_layout)
            self.page_layout.removeItem(self.page_layout.takeAt(self.index_table))
            self.virus_table.deleteLater()
            self.list_strings_widget.deleteLater()
            self.strings_label.deleteLater()
            self.virus_table_label.deleteLater()
            self.static_button.setDisabled(False)
            self.packers_widget.deleteLater()
            self.packers_label.deleteLater()
            self.table_and_strings_layout.deleteLater()

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

        while not os.path.exists(r"E:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\graphics"
                                 r"\virus.exe"):
            print('File does not exists')
            pass

        self.threadpool_sender = QThreadPool()
        worker = Worker(activate_sender)
        self.threadpool_sender.start(activate_sender)

    def activate_vm(self):
        os.chdir(r"C:\Program Files (x86)\VMware\VMware Workstation")
        os.system(r'vmrun -T ws start "C:\Users\u101040.DESHALIT\Documents\Virtual Machines\Windows 10 and later '
                  r'x64\Windows 10 and later x64.vmx"')

        # r"C:\Program Files (x86)\VMware\VMware Workstation"
        # r'vmrun -T ws start "C:\\Users\\user\\OneDrive\\Windows 10 and later x64.vmx"'

    def start_vm(self):
        self.threadpool_vm = QThreadPool()
        worker = Worker(self.activate_vm)
        self.threadpool_vm.start(self.activate_vm)

    def static_analysis(self):

        self.clearLayout()
        self.static_visited = True

        # self.page_layout.addLayout(self.btn_layout)
        self.static_button.setEnabled(False)

        self.virus_table = QTableWidget()
        self.virus_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.virus_table.setMinimumSize(700, 550)

        # Row count
        rows = len_sections("virus.exe")
        self.virus_table.setRowCount(rows + 1)

        # Column count
        self.virus_table.setColumnCount(5)

        sections = sections_entropy("virus.exe")[1:]
        print(sections)

        self.virus_table.setItem(0, 0, QTableWidgetItem("Name"))
        self.virus_table.setItem(0, 1, QTableWidgetItem("Virtual Address"))
        self.virus_table.setItem(0, 2, QTableWidgetItem("Virtual Size"))
        self.virus_table.setItem(0, 3, QTableWidgetItem("Raw Size"))
        self.virus_table.setItem(0, 4, QTableWidgetItem("Entropy"))

        for row in range(0, len(sections)):
            for column in range(len(sections[0])):
                self.virus_table.setItem(row + 1, column, QTableWidgetItem(sections[row][column]))

        self.virus_table.resizeColumnsToContents()
        self.virus_table.resizeRowsToContents()

        # Set the size of the table to the maximum possible value
        self.virus_table.resize(self.virus_table.horizontalHeader().maximumSectionSize(),
                                self.virus_table.verticalHeader().maximumSectionSize())

        window_width = QMainWindow().size().width()
        window_height = QMainWindow().size().height()

        # Set the width of all columns to 100 pixels
        for i in range(self.virus_table.columnCount()):
            self.virus_table.setColumnWidth(i, int(window_width // 2.9))

        # Set the height of all rows to 50 pixels
        for i in range(self.virus_table.rowCount()):
            self.virus_table.setRowHeight(i, window_height // 8)

        self.virus_table.setStyleSheet("""
            QTableWidget {
                background-color: #F8F8FF;
            }
            QTableWidget QTableCornerButton::section {
                background-color: #F8F8FF;
            }
            QTableWidget QTableView {
                color: #000080;
                font-size: 14pt;
                font-family: "Arial";
            }
            QTableWidget QHeaderView {
                background-color: #F0F8FF;
                color: #000080;
                font-size: 12pt;
                font-family: "Arial";
            }
            QTableWidget QTableView::item:selected {
                background-color: #87CEFA;
            }
        """)

        self.table_and_strings_layout = QVBoxLayout()

        self.virus_table_label = make_label("The Portable Executable Table")
        self.table_and_strings_layout.addWidget(self.virus_table_label)
        self.table_and_strings_layout.addWidget(self.virus_table, 0)

        # Create a list widget and add some items to it
        self.list_strings_widget = QListWidget()
        self.list_strings_widget.setMinimumSize(550, 550)

        # YARA
        yara_strings = YaraChecks.check_for_strings("virus.exe")
        yara_packers = YaraChecks.check_for_packer("virus.exe")
        print(yara_packers)

        for dll in yara_strings[0]:
            self.list_strings_widget.addItem(str(dll))

        for string in yara_strings[1]:
            self.list_strings_widget.addItem(str(string.decode()))

        # Create a scroll bar and set its properties
        scrollBar = QScrollBar()
        scrollBar.setOrientation(Qt.Vertical)
        scrollBar.setMinimum(0)
        scrollBar.setMaximum(100)
        scrollBar.setSingleStep(1)
        scrollBar.setPageStep(10)
        scrollBar.setValue(50)

        # Customize the appearance of the scroll bar

        scrollBar_stylesheet = """
            QScrollBar:vertical {
                border: none;
                background: #eee;
                width: 15px;
                margin: 0px 0px 0px 0px;
            }

            QScrollBar::handle:vertical {
                background: #ccc;
                min-height: 20px;
                border-radius: 5px;
            }

            QScrollBar::add-line:vertical {
                background: none;
                height: 0px;
                subcontrol-position: bottom;
                subcontrol-origin: margin;
            }

            QScrollBar::sub-line:vertical {
                background: none;
                height: 0px;
                subcontrol-position: top;
                subcontrol-origin: margin;
            }

            QScrollBar::up-arrow:vertical, QScrollBar::down-arrow:vertical {
                border: none;
                width: 0px;
                height: 0px;
                background: none;
            }

            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }
        """

        scrollBar.setStyleSheet(scrollBar_stylesheet)

        list_widget_style_sheet = """
            QListWidget {
                background-color: #f5f5f5;
                border: 1px solid #ccc;
                border-radius: 5px;
                outline: none;
            }

            QListWidget::item {
                color: #444;
                border: none;
                padding: 10px;
                font-size: 14px;
                font-weight: 500;
            }

            QListWidget::item:hover {
                background-color: #eee;
            }

            QListWidget::item:selected {
                background-color: #333;
                color: #fff;
            }
        """

        self.list_strings_widget.setStyleSheet(list_widget_style_sheet)
        self.strings_label = make_label("Suspicious Strings")
        self.list_strings_widget.setVerticalScrollBar(scrollBar)
        self.table_and_strings_layout.addWidget(self.strings_label)
        self.table_and_strings_layout.addWidget(self.list_strings_widget)

        self.packers_label = make_label("Packers And Protectors")
        self.packers_widget = QListWidget()

        scrollBarPackers = QScrollBar()
        scrollBarPackers.setOrientation(Qt.Vertical)
        scrollBarPackers.setMinimum(0)
        scrollBarPackers.setMaximum(100)
        scrollBarPackers.setSingleStep(1)
        scrollBarPackers.setPageStep(10)
        scrollBarPackers.setValue(50)
        scrollBarPackers.setStyleSheet(scrollBar_stylesheet)

        for packer, tag in yara_packers.items():
            self.packers_widget.addItem(str(packer) + ": " + str(tag[0]))

        self.packers_widget.setMinimumSize(550, 200)
        self.packers_widget.setStyleSheet(list_widget_style_sheet)
        self.packers_widget.setVerticalScrollBar(scrollBarPackers)
        self.table_and_strings_layout.addWidget(self.packers_label)
        self.table_and_strings_layout.addWidget(self.packers_widget)
        self.page_layout.addLayout(self.table_and_strings_layout)

        self.static_visited = True

    def execute_this_fn(self):
        VTScan.scan_directory(self.dir)

    def hash_analysis(self):

        self.clearLayout()
        self.static_visited = False
        self.dynamic_visited = False

        self.dir = str(QFileDialog.getExistingDirectory(self, "Select Directory"))
        self.threadpool_vt = QThreadPool()
        worker = Worker(self.execute_this_fn)
        self.threadpool_vt.start(worker)


app = QApplication(sys.argv)
app.setStyleSheet(qss)
demo = AppDemo()
demo.show()

sys.exit(app.exec())
