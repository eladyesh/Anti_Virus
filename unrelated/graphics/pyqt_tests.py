import sys, os
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5 import QtCore
from PyQt5.QtCore import Qt, QUrl, pyqtSlot, QRunnable, QThreadPool, QVariant, QAbstractTableModel
import PyQt5.QtGui
from PyQt5.QtCore import QObject, QThread, pyqtSignal
import shutil
from poc_start.send_to_vm.sender import Sender
from poc_start.unrelated.hash_scan.vt_hash import VTScan, md5, check_hash, sha_256
from poc_start.unrelated.pe_scan.entropy import *
from poc_start.unrelated.pe_scan.pe_tests import *
from poc_start.unrelated.Yara.ya_ra import YaraChecks
from poc_start.unrelated.fuzzy_hashing.ssdeep_check import *
from threading import Thread
from multiprocessing import Process
from http.server import HTTPServer, BaseHTTPRequestHandler
from queue import Queue, Empty

PATH_TO_MOVE = r"E:\\Cyber\\YB_CYBER\\project\\FinalProject\\poc_start\\poc_start\\unrelated\\graphics"

qss = """
#Window{ 
    background-color: white;
}
QMainWindow {
    background: linear-gradient(to right, #fff, #f5f5f5);
    border-radius: 100px;
    box-shadow: 10px 10px 5px #333;
    font-family: "Courier New", monospace;
    font-size: 16px;
    color: white;
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


def make_label(text, font_size):
    label = QLabel(text)

    # Set the font to a decorative font
    font = QFont('Zapfino', font_size)
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


# Create a model for the table
class TableModel(QAbstractTableModel):
    def __init__(self, data):
        super().__init__()
        self._data = data

    def rowCount(self, parent=None):
        return len(self._data)

    def columnCount(self, parent=None):
        return 2

    def data(self, index, role=Qt.DisplayRole):
        if role == Qt.DisplayRole:
            row = index.row()
            col = index.column()
            return self._data[row][col]
        return QVariant()


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

        self.movie_label = None
        self.delete_widgets = None
        self.fuzzy_spin = None

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

        self.l1 = make_label("YeshScanner", 24)
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
        self.scroll.setStyleSheet("""
        QScrollArea {
          boarder-radius: 20px;
        }
        
        *, *::before, *::after{
        boarder-radius:20px;
        }
        
        QScrollArea QScrollBar {
          /* Styles for all scrollbars */
          border-radius: 100px;
          background-color: #e6b3ff;
        }
        
        QScrollArea QScrollBar::handle {
          /* Styles for the handle (draggable part) of the scrollbar */
          background-color: #d99eff;
          border-radius: 20px;
        }
        
        QScrollArea QScrollBar::add-line,
        QScrollArea QScrollBar::sub-line {
          /* Styles for the buttons on the scrollbar */
          width: 0;
          height: 0;
          border-color: transparent;
          background-color: transparent;
        }
        
        QScrollArea QScrollBar:vertical {
          /* Styles for vertical scrollbars */
          border-top-right-radius: 20px;
          border-bottom-right-radius: 20px;
        }
        
        QScrollArea QScrollBar:horizontal {
          /* Styles for horizontal scrollbars */
          border-top-left-radius: 20px;
          border-top-right-radius: 20px;
        }
        
        QScrollArea QScrollBar:left-arrow,
        QScrollArea QScrollBar:right-arrow,
        QScrollArea QScrollBar:up-arrow,
        QScrollArea QScrollBar:down-arrow {
          /* Styles for the buttons on the scrollbar */
          border-radius: 20px;
          background-color: #e6b3ff;
        }
        
        QScrollArea QScrollBar:vertical:increment,
        QScrollArea QScrollBar:vertical:decrement,
        QScrollArea QScrollBar:horizontal:increment,
        QScrollArea QScrollBar:horizontal:decrement {
          /* Styles for the buttons on the scrollbar */
          border-radius: 20px;
          background-color: #e6b3ff;
        }
        
        QScrollArea QScrollBar:vertical:increment:pressed,
        QScrollArea QScrollBar:vertical:decrement:pressed,
        QScrollArea QScrollBar:horizontal:increment:pressed,
        QScrollArea QScrollBar:horizontal:decrement:pressed {
          /* Styles for the buttons on the scrollbar when pressed */
          border-radius: 20px;
          background-color: #b366ff;
        }
        """)

        self.widget.setLayout(self.page_layout)

        # Scroll Area Properties
        self.scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.scroll.setWidgetResizable(True)
        self.scroll.setWidget(self.widget)

        self.setCentralWidget(self.scroll)

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
            self.imports_label.deleteLater()
            self.pe_tests_label.deleteLater()
            self.table_and_strings_layout.deleteLater()

        if self.hash_visited:
            self.index = self.page_layout.indexOf(self.hash_layout)
            self.page_layout.removeItem(self.page_layout.takeAt(self.index))
            self.virus_total_label.deleteLater()
            self.engine_tree.deleteLater()
            self.basic_info_label.deleteLater()
            self.basic_info.deleteLater()
            self.scan_dir_label.deleteLater()
            self.scan_dir_button.deleteLater()
            if self.movie_label is not None:
                self.movie_label.deleteLater()
                self.show_label = 1
                self.description_for_search.deleteLater()
                self.movie_list.deleteLater()
                self.suspicious_paths.deleteLater()
            self.fuzzy_hash_label.deleteLater()
            self.fuzzy_hash_button.deleteLater()
            if self.delete_widgets is not None:
                for widget in self.delete_widgets:
                    widget.deleteLater()
            if self.fuzzy_spin is not None:
                self.fuzzy_spin.deleteLater()
            if QThreadPool.globalInstance().activeThreadCount() > 0:
                print('here')
                QThreadPool.globalInstance().clear()
            self.hash_layout.deleteLater()

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

    def open_list(self):
        button = self.sender()
        button.setText(button.text().replace("+", "-"))
        if self.list_index[button].isVisible():
            self.list_index[button].setVisible(False)
        else:
            self.list_index[button].setVisible(True)

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
        self.hash_visited = False
        self.dynamic_visited = False

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

        for i in range(5):
            item = self.virus_table.item(0, i)
            flags = item.flags()
            flags &= ~Qt.ItemIsEditable
            item.setFlags(flags)

        for row in range(0, len(sections)):
            for column in range(len(sections[0])):
                self.virus_table.setItem(row + 1, column, QTableWidgetItem(sections[row][column]))
                item = self.virus_table.item(row + 1, column)
                flags = item.flags()
                flags &= ~Qt.ItemIsEditable
                item.setFlags(flags)

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

        self.virus_table_label = make_label("The Portable Executable Table", 24)
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

        self.scrollBar_stylesheet = """
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

        scrollBar.setStyleSheet(self.scrollBar_stylesheet)

        self.list_widget_style_sheet = """
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

        self.list_strings_widget.setStyleSheet(self.list_widget_style_sheet)
        self.strings_label = make_label("Suspicious Strings", 24)
        self.list_strings_widget.setVerticalScrollBar(scrollBar)
        self.table_and_strings_layout.addWidget(self.strings_label)
        self.table_and_strings_layout.addWidget(self.list_strings_widget)

        self.packers_label = make_label("Packers And Protectors", 24)
        self.packers_widget = QListWidget()

        scrollBarPackers = QScrollBar()
        scrollBarPackers.setOrientation(Qt.Vertical)
        scrollBarPackers.setMinimum(0)
        scrollBarPackers.setMaximum(100)
        scrollBarPackers.setSingleStep(1)
        scrollBarPackers.setPageStep(10)
        scrollBarPackers.setValue(50)
        scrollBarPackers.setStyleSheet(self.scrollBar_stylesheet)

        for packer, tag in yara_packers.items():
            self.packers_widget.addItem(str(packer) + ": " + str(tag[0]))

        self.packers_widget.setMinimumSize(550, 200)
        self.packers_widget.setStyleSheet(self.list_widget_style_sheet)
        self.packers_widget.setVerticalScrollBar(scrollBarPackers)
        self.table_and_strings_layout.addWidget(self.packers_label)
        self.table_and_strings_layout.addWidget(self.packers_widget)

        self.imports_label = make_label("Imports", 24)
        self.table_and_strings_layout.addWidget(self.imports_label)

        pe_scan = ScanPE(os.path.abspath("virus.exe").replace("graphics", "hash_scan"))
        dlls = pe_scan.run_pe_scan_exe()
        print(dlls)  # key = tuple - first key: library, value: list of imports

        self.delete_imports = []
        self.list_index = dict({})

        for library, imports in dlls.items():

            h_box_imports = QHBoxLayout()
            imports_button = QPushButton(f"+ {library[0]}")
            imports_button.setMinimumSize(200, 50)
            imports_button.setMaximumSize(200, 50)
            imports_button.setStyleSheet("background-color: green; color: white; border-radius: 10px; "
                                         "justify-content: left; font-size: 15px")

            import_list = QListWidget()
            import_list.setVisible(False)
            import_list.setStyleSheet("""
                       QListWidget {
                           background-color: #f5f5f5;
                           border: 1px solid #ccc;
                           border-radius: 5px;
                           outline: none;
                           justify-content: left;
                           margin: 10px;
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
                   """)
            import_list.setMaximumSize(275, 500)
            import_list.setMinimumSize(275, 300)

            for imp in imports:
                import_list.addItem(str(imp))

            self.list_index[imports_button] = import_list
            imports_button.clicked.connect(lambda: self.open_list())

            h_box_imports.addWidget(imports_button)
            h_box_imports.addWidget(import_list)
            h_box_imports.setAlignment(Qt.AlignLeft)

            self.delete_imports.append(h_box_imports)
            self.delete_imports.append(imports_button)
            self.delete_imports.append(import_list)
            self.table_and_strings_layout.addLayout(h_box_imports)


        # PE TESTS
        self.pe_tests_label = make_label("PE examination", 24)
        self.table_and_strings_layout.addWidget(self.pe_tests_label)

        self.page_layout.addLayout(self.table_and_strings_layout)
        self.static_visited = True

    def activate_vt_scan_dir(self):

        for path in VTScan.scan_directory(self.dir):
            self.suspicious_paths.addItem(str(path))

    def scan_dir(self):

        self.dir = str(QFileDialog.getExistingDirectory(self, "Select Directory"))
        self.threadpool_vt = QThreadPool()
        self.show_movie()

        self.suspicious_paths = QListWidget()
        list_widget_style_sheet = """
             QListWidget {
                 background-color: #f5f5f5;
                 border: 1px solid #ccc;
                 border-radius: 5px;
                 outline: none;
                 margin: 20px;
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
        self.suspicious_paths.setStyleSheet(list_widget_style_sheet)

        scrollBarPaths = QScrollBar()
        scrollBarPaths.setOrientation(Qt.Vertical)
        scrollBarPaths.setMinimum(0)
        scrollBarPaths.setMaximum(100)
        scrollBarPaths.setSingleStep(1)
        scrollBarPaths.setPageStep(10)
        scrollBarPaths.setValue(50)

        scrollBarPaths_stylesheet = """
             QScrollBar:vertical {
                 border: none;
                 background: #eee;
                 width: 15px;
                 margin: 0px 0px 0px 0px;

             QScrollBar::handle:vertical {
                 background: #ccc;
                 min-height: 20px;
                 border-radius: 5px;

             QScrollBar::add-line:vertical {
                 background: none;
                 height: 0px;
                 subcontrol-position: bottom;
                 subcontrol-origin: margin;

             QScrollBar::sub-line:vertical {
                 background: none;
                 height: 0px;
                 subcontrol-position: top;
                 subcontrol-origin: margin;

             QScrollBar::up-arrow:vertical, QScrollBar::down-arrow:vertical {
                 border: none;
                 width: 0px;
                 height: 0px;
                 background: none;

             QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                 background: none;
             }
         """

        scrollBarPaths.setStyleSheet(scrollBarPaths_stylesheet)
        self.suspicious_paths.setVerticalScrollBar(scrollBarPaths)
        self.suspicious_paths.setMaximumSize(550, 350)
        self.movie_list.addWidget(self.suspicious_paths)
        self.hash_layout.insertLayout(self.hash_layout.indexOf(self.description_for_search) + 1, self.movie_list)

        worker = Worker(self.activate_vt_scan_dir)
        self.threadpool_vt.start(worker)

    def show_movie(self):

        if self.show_label == 1:
            self.description_for_search = make_label("Now, if a file was found malicious by more than 5 engines\n"
                                                     "it will be shown on the screen to your right", 15)
            self.hash_layout.insertWidget(self.hash_layout.indexOf(self.scan_dir_button) + 1,
                                          self.description_for_search)

            # Create the QLabel
            self.movie_label = QLabel()
            self.movie_list = QHBoxLayout()

            # Set the GIF image as the QLabel's movie
            movie = QMovie('file_scan.gif')
            self.movie_label.setMovie(movie)

            # Start the movie
            movie.start()
            self.movie_list.addWidget(self.movie_label)
            self.show_label = 0

    def create_top_level(self):

        self.dialog = QDialog(self)
        self.dialog.setWindowTitle("Loading Data")

        # Create the QLabel
        movie_label = QLabel()
        self.show_loading = make_label("Loading Hashes...", 24)

        # Set the GIF image as the QLabel's movie
        movie = QMovie('loading-circle-loading.gif')
        movie_label.setMovie(movie)

        # Start the movie
        movie.start()
        v_box_loading = QVBoxLayout()
        v_box_loading.addWidget(self.show_loading)
        v_box_loading.addWidget(movie_label)
        self.dialog.setLayout(v_box_loading)
        self.dialog.exec_()

    def wait_for_threads(self, threads):

        for thread in threads:
            thread.waitForDone()

    def fuzzy_scanning(self):

        fuzzy_label = QLabel()

        # Set the font color to black
        fuzzy_label.setStyleSheet("color: black")

        # Set the font to a cool font
        font = QFont("Arial", 18, QFont.Bold)
        fuzzy_label.setFont(font)

        # Add a drop shadow to the font
        fuzzy_label.setStyleSheet("QLabel { text-shadow: 2px 2px 2px #000000; }")
        self.fuzzy_spin = QHBoxLayout()

        # create a spin box
        spin_box = QSpinBox()

        # set the range and step size
        spin_box.setRange(0, 100)
        spin_box.setSingleStep(5)

        # set the starting value
        spin_box.setValue(0)

        # set the suffix and prefix
        spin_box.setPrefix("Number of hashes match: ")

        # set the wrap mode
        spin_box.setWrapping(True)
        spin_box.setReadOnly(True)

        # set the custom stylesheet
        spin_box.setStyleSheet(
            """
            QSpinBox {
                background-color: #fafafa;
                color: #333333;
                border: 1px solid #cccccc;
                border-radius: 5px;
                font-size: 16px;
                padding: 5px;
            }
            """
        )

        self.fuzzy_spin.addWidget(fuzzy_label)
        self.fuzzy_spin.addWidget(spin_box)
        self.hash_layout.addLayout(self.fuzzy_spin)
        self.delete_widgets = [spin_box, fuzzy_label]

        h1 = ppdeep.hash_from_file("virus.exe")

        class ThreadTask_49(QRunnable):
            def run(self):
                search_49_file(h1)

        class ThreadTask_79(QRunnable):
            def run(self):
                search_79_file(h1)

        class ThreadTask_label(QRunnable):
            def run(self):
                change_fuzzy_label(fuzzy_label)

        class ThreadTask_Spin(QRunnable):
            def run(self):
                change_spin_counter(spin_box)

        class WaitThread(QThread):
            def run(self):
                QThreadPool.globalInstance().waitForDone()

        # create and start the first thread
        thread1 = ThreadTask_49()
        QThreadPool.globalInstance().start(thread1)

        # create and start the second thread
        thread2 = ThreadTask_79()
        QThreadPool.globalInstance().start(thread2)

        thread3 = ThreadTask_label()
        QThreadPool.globalInstance().start(thread3)

        # create and start the second thread
        # thread4 = ThreadTask_Spin()
        # QThreadPool.globalInstance().start(thread4)

        # create the wait thread and start it in a separate thread
        wait_thread = WaitThread()
        wait_thread.start()

    def hash_analysis(self):

        self.clearLayout()
        self.static_visited = False
        self.dynamic_visited = False

        self.hash_layout = QVBoxLayout()
        self.engine_tree = QTreeWidget()
        self.engine_tree.setHeaderLabels(['Name', 'Version', 'Category', 'Result', 'Method', 'Update'])

        md5_hash = md5("virus.exe")
        sha_256_hash = sha_256("virus.exe")
        entropy_of_file = entropy_for_file("virus.exe")
        vtscan = VTScan()

        show_tree = True
        engines, malicious, undetected = vtscan.info(md5_hash)
        if engines == 0 and malicious == 0 and undetected == 0:
            show_tree = False

        self.basic_info_label = make_label("Basic Information", 24)
        self.hash_layout.addWidget(self.basic_info_label)

        # Create the QTableView
        self.basic_info = QTableView()

        if show_tree:
            # Set the model on the QTableView
            data = [
                ['MD5 hash', md5_hash],
                ['SHA-256 hash', sha_256_hash],
                ['Entropy of file', entropy_of_file],
                ['Number of engines detected as Malicious', malicious],
                ['Number of engines not detected as Malicious', undetected],
                ['File type', 'Win32 Exe']
            ]
            model = TableModel(data)
            self.basic_info.setModel(model)

            # Set the style sheet and disable editing
            style_sheet = """
            QTableView {
                font-family: "Arial Black";
                font-size: 10pt;
                color: #333;
                background-color: #f5f5f5;
                border: 2px solid #ccc;
                border-radius: 5px;
            }
            QTableView::item {
                padding: 10px;
                background-color: #b3d9ff;
            }
            QTableView::item:selected {
                background-color: #99ccff;
                color: #fff;
            }
            QTableView::item:selected:!active {
                background-color: #3399ff;
                color: #fff;
            }
            QTableView::item:selected:active {
            background-color: #3399ff;
                color: #fff;
            }
            QHeaderView {
                font-size: 18pt;
                font-weight: bold;
                color: #333;
                background-color: #f5f5f5;
                border: 1px solid #ccc;
                border-radius: 5px;
            }
            QHeaderView::section {
                padding: 10px;
            }
            QHeaderView::section:selected {
                background-color: #3399ff;
                color: #fff;
            }
            """

            self.basic_info.setStyleSheet(style_sheet)
            self.basic_info.setEditTriggers(QTableView.NoEditTriggers)

            # Allow the cells to be resized using the mouse
            self.basic_info.horizontalHeader().setSectionsMovable(True)
            self.basic_info.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
            self.basic_info.setMinimumSize(550, 360)
            self.hash_layout.addWidget(self.basic_info)

            self.virus_total_label = make_label("Virus Total Engine Results", 24)
            self.hash_layout.addWidget(self.virus_total_label)

            # Add a top-level item for each engine
            for engine in engines:
                # Create a QTreeWidgetItem for the engine
                item = QTreeWidgetItem(
                    [engine['name'], engine['version'], str(engine['category']), str(engine['result']),
                     str(engine['method']), str(engine['update'])])

                # # Set additional data for the item using setData
                # item.setData(0, 0, engine['name'])
                # item.setData(1, 0, engine['type'])
                # item.setData(2, 0, engine['thrust'])
                # item.setData(3, 0, engine['weight'])

                # Add the item to the tree
                self.engine_tree.addTopLevelItem(item)

            # Set the style sheet for the tree widget
            self.engine_tree.setStyleSheet('''
                QTreeWidget {
                    font-family: sans-serif;
                    font-size: 14px;
                    color: white;
                    background-color: #333;
                    border: 2px solid #444;
                    gridline-color: #666;
                }
                QTreeWidget::item {
                    padding: 5px;
                    margin: 0px;
                }
                QTreeWidget::item:hover {
                    background-color: #555;
                }
                QTreeWidget::item:selected {
                    background-color: #777;
                }
                QTreeWidget::item:selected:active {
                    background-color: #999;
                }
                QTreeWidget::item:selected:!active {
                    background-color: #bbb;
                }
                QTreeWidget::indicator {
                    width: 16px;
                    height: 16px;
                }
                QTreeWidget::indicator:unchecked {
                    border: 1px solid white;
                }
                QTreeWidget::indicator:unchecked:hover {
                    border: 1px solid #aaa;
                }
                QTreeWidget::indicator:unchecked:pressed {
                    border: 1px solid #555;
                }
                QTreeWidget::indicator:checked {
                    background-color: white;
                }
                QTreeWidget::indicator:checked:hover {
                    background-color: #aaa;
                }
                QTreeWidget::indicator:checked:pressed {
                    background-color: #555;
                }
                QTreeWidget::indicator:indeterminate {
                    background-color: white;
                    border: 1px dotted white;
                }
                QTreeWidget::indicator:indeterminate:hover {
                    background-color: #aaa;
                    border: 1px dotted #aaa;
                }
                QTreeWidget::indicator:indeterminate:pressed {
                    background-color: #555;
                    border: 1px dotted #555;
                }
                QTreeWidget::branch {
                    background: transparent;
                }
                QTreeWidget::branch:closed:has-children {
                    image: none;
                    border: 0px;
                }
                QTreeWidget::branch:open:has-children {
                    image: none;
                    border: 0px;
                }
                QTreeWidget::branch:has-children:!has-siblings:closed,
                QTreeWidget::branch:closed:has-children:has-siblings {
                    image: none;
                    border: 0px;
                }
                QTreeWidget::branch:open:has-children:has-siblings  {
                    image: none;
                    border: 0px;
                }
                QTreeWidget::header {
                    font-size: 24px;
                    font-weight: bold;
                    background-color: #444;
                    border: 2px solid #555;
                    min-height: 20px;
                }
                QTreeWidget::item {
                    min-height: 30px;
                    min-width: 400px;
                    width: 200px;
                }
            ''')

            self.engine_tree.setMinimumSize(550, 550)
            self.hash_layout.addWidget(self.engine_tree)

        else:

            # Create the label
            label = QLabel("We're sorry, we couldn't upload your file to VirusTotal :(")

            # Set the font color to red
            label.setStyleSheet("color: red")

            # Set the font to a bold italicized serif font
            font = QFont("Arial", 18, QFont.Bold, True)
            label.setFont(font)

            # Add some padding to the label
            label.setStyleSheet("QLabel { padding: 20px; }")
            self.hash_layout.addWidget(label)

        self.page_layout.addLayout(self.hash_layout)

        self.scan_dir_label = make_label("Directory Analysis", 24)
        self.hash_layout.addWidget(self.scan_dir_label)

        # Set the style sheet
        scan_dir_style_sheet = """
        QPushButton {
            font-size: 18pt;
            font-weight: bold;
            color: #fff;
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                        stop: 0 #9933ff, stop: 1 #6600cc);
            border: 2px solid #6600cc;
            border-radius: 10px;
            padding: 10px;
            min-width: 100px;
            min-height: 50px;
        }
        QPushButton:hover {
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                        stop: 0 #b366ff, stop: 1 #8000ff);
        }
        QPushButton:pressed {
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                        stop: 0 #cc99ff, stop: 1 #9933ff);
        }
        """
        self.scan_dir_button = QPushButton('Scan Dir for viruses')
        self.scan_dir_button.setStyleSheet(scan_dir_style_sheet)
        self.scan_dir_button.setMaximumSize(300, 50)
        self.scan_dir_button.clicked.connect(self.scan_dir)

        self.show_label = 1
        self.hash_layout.addWidget(self.scan_dir_button)

        self.fuzzy_hash_label = make_label("Fuzzy Hashing Analysis", 24)
        self.fuzzy_hash_button = QPushButton("Scan Virus With Fuzzy Hashing")
        self.fuzzy_hash_button.setStyleSheet(scan_dir_style_sheet)
        self.fuzzy_hash_button.setMaximumSize(550, 350)
        self.hash_layout.addWidget(self.fuzzy_hash_label)
        self.hash_layout.addWidget(self.fuzzy_hash_button)

        self.fuzzy_hash_button.clicked.connect(self.fuzzy_scanning)
        self.hash_visited = True


app = QApplication(sys.argv)
app.setStyleSheet(qss)
demo = AppDemo()
demo.show()

sys.exit(app.exec())
