import sys, os
import random
import threading
import socket
import pydivert
import pyuac
from pydivert import WinDivert
from pyuac import main_requires_admin
from PyQt5.QtWidgets import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5 import QtCore, QtGui
from PyQt5.QtCore import Qt, QUrl, pyqtSlot, QRunnable, QThreadPool, QVariant, QAbstractTableModel, QRectF
import PyQt5.QtGui
from PyQt5.QtCore import QObject, QThread, pyqtSignal
import shutil
from poc_start.unrelated.graphics.quarantine import Quarantine
from poc_start.unrelated.graphics.helpful_widgets import DialWatch, EventViewer
from poc_start.send_to_vm.sender import Sender
from poc_start.unrelated.hash_scan.vt_hash import VTScan, md5, check_hash, sha_256, start_server, RequestHandler, \
    HTTPServer, BaseHTTPRequestHandler
from poc_start.unrelated.pe_scan.entropy import *
from poc_start.unrelated.pe_scan.pe_tests import *
from poc_start.unrelated.Yara.ya_ra import YaraChecks
from poc_start.unrelated.fuzzy_hashing.ssdeep_check import *
from poc_start.unrelated.virus_db.redis_virus import Redis
from poc_start.unrelated.pe_scan.language import Packers
from poc_start.unrelated.graphics.terms_and_services import TermsAndServicesDialog, terms_and_service
from poc_start.unrelated.python_exe.virus_scan import PythonVirus
from poc_start.unrelated.sys_internals.extract import SysInternals
from threading import Thread
from multiprocessing import Process
from http.server import HTTPServer, BaseHTTPRequestHandler
from queue import Queue, Empty
import types
import functools
import pickle
import matplotlib
from qtwidgets import Toggle, AnimatedToggle

matplotlib.use("Qt5Agg")
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt
import numpy as np
import colorcet as cc

PATH_TO_MOVE = os.getcwd()
# print(PATH_TO_MOVE) # r"D:\\Cyber\\YB_CYBER\\project\\FinalProject\\poc_start\\poc_start\\unrelated\\graphics"

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

bubble_strings_dict = {
    'CreateToolhelp32Snapshot': 'Takes a snapshot of the specified processes, as well as '
                                'the heaps, modules, and threads used by these '
                                'processes', 'Process32First': 'Retrieves information '
                                                               'about the first process '
                                                               'encountered in a system '
                                                               'snapshot',
    'Process32Next': 'Retrieves information about the next process recorded in a system '
                     'snapshot', 'LoadLibrary': 'Loads the specified  module into the '
                                                'address space of the calling process',
    'GetProcAddress': 'Retrieves the address of an exported function (also known as a '
                      'procedure) or variable from the specified dynamic-link library ('
                      'DLL)', 'GetModuleHandle': 'Retrieves a module handle for the '
                                                 'specified module', 'SetWindowsHookEx':
        'Installs an application-defined hook procedure into a hook chain', 'GetMessage':
        "Retrieves a message from the calling thread's message queue", 'CallNextHookEx':
        'Passes the hook information to the next hook procedure in the current hook '
        'chain', 'OpenClipboard': 'Opens the clipboard for examination and prevents other '
                                  'applications from modifying the clipboard content',
    'GetClipboardData': 'Retrieves data from the clipboard in a specified format',
    'CloseClipboard': 'Closes the clipboard', 'RegOpenKeyExA': 'Opens the specified '
                                                               'registry key',
    'RegSetValueExA': 'Sets the data and type of a specified value under a registry key',
    'RegCreateKeyExA': 'Creates the specified registry key', 'RegGetValueA': 'Retrieves '
                                                                             'the type '
                                                                             'and data '
                                                                             'for the '
                                                                             'specified '
                                                                             'registry '
                                                                             'value',
    'socket': 'The socket function creates a socket that is bound to a specific transport '
              'service provider.', 'recv': 'The recv function receives data from a '
                                           'connected socket or a bound connectionless '
                                           'socket.', 'connect': 'The connect function '
                                                                 'establishes a '
                                                                 'connection to a '
                                                                 'specified socket.',
    'send': 'The send function sends data on a connected socket.', 'CreateFileA':
        'Creates or opens '
        'a file or I/O '
        'device',
    'DeleteFileA': 'Deletes an existing file', 'WriteFileEx': 'Writes data to the '
                                                              'specified file or '
                                                              'input/output (I/O) '
                                                              'device', 'WriteFile':
        'Writes data to the specified file or input/output (I/O) device', 'VirtualAlloc':
        'Reserves, commits, or changes the state  of a region of pages in the virtual '
        'address space of the calling process', 'VirtualAllocEx': 'Reserves, commits, '
                                                                  'or changes the state  '
                                                                  'of a region of memory '
                                                                  'within the virtual '
                                                                  'address space of a '
                                                                  'specified process',
    'WriteProcessMemory': 'Writes data to an area of memory in a specified process',
    'CreateThread': 'Creates a thread to execute within the virtual address space of the '
                    'calling process', 'CreateRemoteThread': 'Creates a thread that runs '
                                                             'in the virtual address '
                                                             'space of another process',
    'CloseHandle': 'Closes an open object handle',
    'KERNEL32': "Kernel32.dll is a dynamic link library (DLL) file that is an essential "
                "component of the Windows operating system.", "ADVAPI32":
        "Advapi32. dll is a part of the advanced API services library. It provides access to advanced "
        "functionality that "
        "comes in addition to the kernel.", "Ws2_32": "The Ws2_32.dll loads the service "
                                                      "provider's interface DLL into the "
                                                      "system by using the standard "
                                                      "Microsoft Windows dynamic library "
                                                      "loading mechanisms, "
                                                      "and initializes it by calling "
                                                      "WSPStartup.", "USER32": "user32.dll is a Dynamic "
                                                                               "Link Library (DLL) file "
                                                                               "that contains functions "
                                                                               "for handling user input "
                                                                               "and user interface "
                                                                               "elements on Windows "
                                                                               "operating systems. ",
    "SOFTWARE\\Policies\\Microsoft\\Windows Defender": "A registry key in the Windows "
                                                       "operating system that is used to "
                                                       "configure various settings for "
                                                       "Windows Defender, which is the "
                                                       "built-in antivirus and malware "
                                                       "protection software in Windows.",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run": "A registry key located in the "
                                                         "Windows Registry. It is used to "
                                                         "configure applications or "
                                                         "scripts to run automatically "
                                                         "when a user logs in to the "
                                                         "system",
    # now moving to packers
    "PackerUPX_CompresorGratuito_wwwupxsourceforgenet": "Packers like UPX are used to scramble and mask "
                                                        "in an effort to make it more difficult for the "
                                                        "analyst/reverser to figure out what is going "
                                                        "on.",
    "UPX_wwwupxsourceforgenet_additional": "Packers like UPX are used to scramble and mask "
                                           "in an effort to make it more difficult for the "
                                           "analyst/reverser to figure out what is going "
                                           "on.",
    "yodas_Protector_v1033_dllocx_Ashkbiz_Danehkar_h": "A signature that recognizes malware given by MalShare",
    "Netopsystems_FEAD_Optimizer_1": "A signature that recognizes malware given by MalShare",
    "UPX_290_LZMA": "Packers like UPX are used to scramble and mask "
                    "in an effort to make it more difficult for the "
                    "analyst/reverser to figure out what is going "
                    "on.",
    "UPX_290_LZMA_Markus_Oberhumer_Laszlo_Molnar_John_Reiser": "Packers like UPX are used to scramble and mask "
                                                               "in an effort to make it more difficult for the "
                                                               "analyst/reverser to figure out what is going "
                                                               "on.",
    "UPX_290_LZMA_additional": "Packers like UPX are used to scramble and mask "
                               "in an effort to make it more difficult for the "
                               "analyst/reverser to figure out what is going "
                               "on.",
    "UPX_wwwupxsourceforgenet": "Packers like UPX are used to scramble and mask "
                                "in an effort to make it more difficult for the "
                                "analyst/reverser to figure out what is going "
                                "on.", "Microsoft_Visual_Cpp_V80_Debug": "A basic signature of exe written in "
                                                                         "c++ language version 8.0",
    "Microsoft_Visual_Cpp_80_Debug_": "A basic signature of exe written in c++ language version 8.0",
    "Microsoft_Visual_Cpp_80_Debug": "A basic signature of exe written in c++ language version 8.0 ",
    "OpenProcess": "Opens an existing local process object.", "Microsoft_Visual_Cpp_80": "A basic signature of exe "
                                                                                         "written in c++ language "
                                                                                         "version 8.0 ",
}


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
    # label.setGraphicsEffect(shadow)

    return label


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
        return len(self._data[0])

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

        self.movie = QMovie("images/drag_and_drop.gif")
        self.gif_label = QLabel(self)
        self.gif_label.setMovie(self.movie)
        self.gif_label.setFixedSize(350, 200)
        # self.gif_label.move(int((self.rect().width() - self.gif_label.width()) / 2), int((self.rect().height() - self.gif_label.height()) / 2))
        self.gif_label.move(int(self.width() / 1.8), -int(self.height() / 4.8))
        self.movie.start()

        # self.move(QApplication.desktop().screen().rect().center()- self.rect().center())
        # self.resize(300, 300)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.gif_label.move(int(self.width() / 3.3), -int(self.height() / 11))

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
            self.movie.stop()
            self.gif_label.deleteLater()
        else:
            event.ignore()


class AppDemo(QMainWindow):

    def __init__(self):
        super().__init__()

        self.flag = False
        self.setWindowTitle("AntiVirus")
        self.setWindowIcon(QIcon("images/virus.png"))

        # toolbar
        self.toolbar = QToolBar()
        self.toolbar.setMovable(False)

        # Add actions to the toolbar
        self.main_menu_action = QAction(QIcon("images/main_menu.png"), "main_menu", self)
        self.main_menu_action.triggered.connect(lambda: self.main_menu_window())

        # self.file_analysis_action = QAction(QIcon("images/exe_analysis.png"), "file_analysis", self)
        # self.file_analysis_action.triggered.connect(lambda: self.show_loading_menu())

        self.directory_analysis = QAction(QIcon("images/directory_analysis.png"), "Scan Directory", self)
        self.directory_analysis.triggered.connect(self.show_directory_analysis)

        self.ip_analysis_action = QAction(QIcon("images/ip_analysis.png"), "Scan IP", self)
        self.ip_analysis_action.triggered.connect(self.show_ip_analysis)

        self.about_action = QAction(QIcon("images/info-button.png"), "Info", self)
        self.about_action.triggered.connect(lambda: terms_and_service(False))

        self.settings_action = QAction(QIcon("images/settings.png"), "Change Settings", self)
        self.settings_action.triggered.connect(lambda: self.show_settings())

        self.toolbar.addAction(self.main_menu_action)
        # self.toolbar.addAction(self.file_analysis_action)
        self.toolbar.addAction(self.directory_analysis)
        self.toolbar.addAction(self.ip_analysis_action)
        self.toolbar.addAction(self.about_action)
        self.toolbar.addAction(self.settings_action)

        with open("css_files/toolbar.css") as f:
            self.toolbar.setStyleSheet(f.read())

        self.addToolBar(Qt.LeftToolBarArea, self.toolbar)

        # for database
        self.run_for_start = False
        self.run_for_entropy = 1
        self.run_for_rules = 1
        self.run_for_packers = 1
        self.run_for_fractioned = 1
        self.run_for_sections = 1
        self.run_for_linker = 1
        self.run_for_engines = 1
        self.run_for_suspicious = 1
        self.run_for_cpu = 1
        self.run_for_identifies = 1

        self.main_menu_window()

    def update_dial_position(self, event=None):

        # Calculate the new position of the label widget based on the size of the window
        label_width = self.dial.sizeHint().width()
        window_width = self.width()
        x = window_width - label_width
        self.dial.move(x - 20, 20)

    def show_settings(self):

        self.clearLayout()
        self.dynamic_visited = False
        self.static_visited = False
        self.ip_visited = False
        self.hash_visited = False
        self.dir_visited = False

        self.settings_layout = QVBoxLayout()
        self.page_layout.addLayout(self.settings_layout)

        self.vt_toggel = AnimatedToggle(
            checked_color="green",
            pulse_checked_color="red"
        )
        self.vt_toggel.setMaximumSize(100, 50)
        self.vt_message = QLabel("Do you want to activate Virus Total search?")
        self.vt_message.setFont(QFont("Zapfino", 16))
        self.vt_hbox = QHBoxLayout()
        self.vt_hbox.addWidget(self.vt_message)
        self.vt_hbox.addWidget(self.vt_toggel)

        self.data_base_toggle = AnimatedToggle(
            checked_color="green",
            pulse_checked_color="red"
        )
        self.data_base_toggle.setMaximumSize(100, 50)
        self.data_base_message = QLabel("Do you want your suspicious file to be saved in our data base?")
        self.data_base_message.setFont(QFont("Zapfino", 16))
        self.data_base_hbox = QHBoxLayout()
        self.data_base_hbox.addWidget(self.data_base_message)
        self.data_base_hbox.addWidget(self.data_base_toggle)
        self.settings_layout.addLayout(self.data_base_hbox)

        self.settings_layout.addLayout(self.vt_hbox)
        self.settings_visited = True

        # TODO - complete settings, and python

    def run_func_in_thread(self, func_to_run):

        self.thread = QThread()
        self.thread.run = func_to_run
        return self.thread

    def show_loading_menu(self):

        # self.clearLayout()

        class GifThread(QThread):
            def __init__(self, label, movie):
                QThread.__init__(self)
                self.label = label
                self.movie = movie

            def run(self):
                self.movie.start()

        class OverlayWindow(QMainWindow):
            def __init__(self):
                super().__init__()
                self.initUI()

            def initUI(self):
                self.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.WindowStaysOnTopHint)
                # self.setAttribute(QtCore.Qt.WA_TranslucentBackground)

                # Create the label for the gif

                self.label_load = QLabel()
                movie = QMovie("loading.gif")
                self.label_load.setMovie(movie)

                # Create the label for the text
                self.text_label = QLabel("Loading your data...")
                self.label_load.setAlignment(QtCore.Qt.AlignCenter)

                # Style the text label
                font = QFont()
                font.setFamily("Zapfino")
                font.setPointSize(20)
                font.setBold(True)
                self.text_label.setFont(font)
                self.text_label.setStyleSheet("color: #0096FF;")
                self.text_label.setAlignment(QtCore.Qt.AlignCenter)

                # Create the main layout
                self.layout_load = QVBoxLayout()
                self.layout_load.addWidget(self.label_load, 0, QtCore.Qt.AlignCenter)
                self.layout_load.addWidget(self.text_label, 0, QtCore.Qt.AlignBottom)

                loading_thread = GifThread(self.label_load, movie)
                loading_thread.run()
                central_widget = QWidget(self)
                central_widget.setLayout(self.layout_load)
                self.setCentralWidget(central_widget)

                close_button = QPushButton('X', self)
                close_button.setFixedSize(30, 30)
                close_button.clicked.connect(self.close)

            def mousePressEvent(self, event):
                self.offset = event.pos()

            def mouseMoveEvent(self, event):
                x = event.globalX()
                y = event.globalY()
                x_w = self.offset.x()
                y_w = self.offset.y()
                self.move(x - x_w, y - y_w)

        self.overlay = OverlayWindow()
        self.overlay.show()

    def clearLayout(self):

        if self.run_once == 0:

            for cnt in reversed(range(self.page_layout.count())):
                if cnt == 0 or cnt == 1 or cnt == 2:
                    continue
                widget = self.page_layout.takeAt(cnt).widget()
                if widget is not None:
                    widget.deleteLater()

            if self.load_for_hash:
                self.load_for_hash.deleteLater()

            if self.load_for_static:
                self.load_for_static.deleteLater()

            index = self.page_layout.indexOf(self.static_hash_load)
            self.page_layout.removeItem(self.page_layout.takeAt(index))
            # self.start_label_explantion.deleteLater()

            # self.activate_btn_layout.deleteLater()
            self.start_vm_btn.deleteLater()
            self.btn.deleteLater()
            self.run_once = 1

        if self.static_visited:
            self.index_table = self.page_layout.indexOf(self.table_and_strings_layout)
            self.page_layout.removeItem(self.page_layout.takeAt(self.index_table))
            self.virus_table.deleteLater()
            self.list_strings_widget.deleteLater()
            self.sys_internals_strings_list.deleteLater()
            self.sys_internals_strings_label.deleteLater()
            self.strings_label.deleteLater()
            self.virus_table_label.deleteLater()
            self.static_button.setDisabled(False)
            self.packers_widget.deleteLater()
            self.packers_label.deleteLater()
            self.imports_label.deleteLater()
            self.tree_imports.deleteLater()

            self.pe_tests_label.deleteLater()
            self.h_box_for_groupbox.deleteLater()
            self.pe_linker.deleteLater()
            self.fractioned.deleteLater()
            self.suspicious_imports.deleteLater()
            self.table_and_strings_layout.deleteLater()

        if self.hash_visited:
            self.index = self.page_layout.indexOf(self.hash_layout)
            self.page_layout.removeItem(self.page_layout.takeAt(self.index))
            if self.virus_total_label is not None:
                self.virus_total_label.deleteLater()
                self.engine_tree.deleteLater()

            self.basic_info_label.deleteLater()
            self.basic_info.deleteLater()

            self.fuzzy_hash_label.deleteLater()
            self.fuzzy_hash_button.deleteLater()
            if self.delete_widgets is not None:
                for widget in self.delete_widgets:
                    widget.deleteLater()
            if self.fuzzy_spin is not None:
                self.fuzzy_spin.deleteLater()

            if self.thread1 is not None and self.thread2 is not None and self.thread3 is not None and self.thread4 is not None:
                self.thread1.terminate()
                self.thread2.terminate()
                self.thread3.terminate()
                self.thread4.terminate()

            self.hash_layout.deleteLater()

        if self.dynamic_visited:
            self.start_dynamic.deleteLater()
            self.tree_functions.deleteLater()
            for widget in self.delete_funcs:
                widget.deleteLater()
            # self.grid_button_layout.deleteLater()
            self.graph_button.deleteLater()
            self.handle_label.deleteLater()
            self.events_table.deleteLater()
            self.dynamic_layout.deleteLater()

        if self.dir_visited:
            self.scan_dir_label.deleteLater()
            self.scan_dir_button.deleteLater()
            if self.movie_label is not None:
                self.movie_label.deleteLater()
                self.show_label = 1
                self.description_for_search.deleteLater()
                self.progress_bar_dir.deleteLater()
                self.description_progress.deleteLater()
                self.movie_list.deleteLater()
                self.suspicious_paths.deleteLater()
                self.threadpool_vt.terminate()
                self.dir_layout.deleteLater()

        if self.ip_visited:
            self.ip_analysis_label.deleteLater()
            self.ip_button.deleteLater()
            if self.movie_label_ip is not None:
                self.show_label_ip = 1
                self.description_for_ip_analysis.deleteLater()
                self.progress_bar_ip.deleteLater()
                self.description_progress_ip.deleteLater()
                self.movie_list_ip.deleteLater()
                self.suspicious_ip.deleteLater()
                self.movie_label_ip.deleteLater()
                self.ip_thread.terminate()

            self.ip_layout.deleteLater()

        if self.settings_visited:
            self.vt_toggel.deleteLater()
            self.vt_message.deleteLater()
            self.vt_hbox.deleteLater()
            self.data_base_toggle.deleteLater()
            self.data_base_message.deleteLater()
            self.data_base_hbox.deleteLater()

            self.settings_layout.deleteLater()

    def show_ip_analysis(self):

        self.clearLayout()
        self.dir_visited = False
        self.static_visited = False
        self.hash_visited = False
        self.dynamic_visited = False
        self.ip_visited = True
        self.settings_visited = False

        # Set the style sheet
        scan_dir_style_sheet = """
             QPushButton {
                 background-color: #E7E7FA;
                 color: #000080;
                 border: 2px solid #9400D3;
                 font: bold 25px;
                 min-width: 80px;
                 margin: 5px;
                 margin-bottom: 10px;
                 padding: 10px;
             }

             QPushButton:hover {
                 background-color: #D8BFD8;
                 color: #4B0082;
             }

             QPushButton:pressed {
                 background-color: #DDA0DD;
                 color: #8B008B;
             }
         """

        # IP analysis
        self.ip_layout = QVBoxLayout()
        self.ip_analysis_label = make_label("IP Analysis", 24)
        self.ip_layout.addWidget(self.ip_analysis_label)

        self.ip_button = QPushButton("Scan network for suspicious used IP's")
        self.ip_button.setStyleSheet(scan_dir_style_sheet)

        self.show_analysis_label = 1
        self.ip_button.clicked.connect(self.ip_analysis)
        self.ip_button.setMaximumSize(550, 250)
        self.ip_layout.addWidget(self.ip_button)
        self.page_layout.addLayout(self.ip_layout)

    def show_directory_analysis(self):

        self.clearLayout()
        self.hash_visited = False
        self.static_visited = False
        self.dynamic_visited = False
        self.ip_visited = False
        self.settings_visited = False

        self.show_label = 1
        self.dir_layout = QVBoxLayout()
        self.page_layout.addLayout(self.dir_layout)

        self.scan_dir_label = make_label("Directory Analysis", 24)
        self.dir_layout.addWidget(self.scan_dir_label)

        # Set the style sheet
        scan_dir_style_sheet = """
            QPushButton {
                background-color: #E7E7FA;
                color: #000080;
                border: 2px solid #9400D3;
                font: bold 25px;
                min-width: 80px;
                margin: 5px;
                margin-bottom: 10px;
                padding: 10px;
            }

            QPushButton:hover {
                background-color: #D8BFD8;
                color: #4B0082;
            }

            QPushButton:pressed {
                background-color: #DDA0DD;
                color: #8B008B;
            }
        """
        self.scan_dir_button = QPushButton('Scan Dir for viruses')
        self.scan_dir_button.setStyleSheet(scan_dir_style_sheet)
        self.scan_dir_button.setMaximumSize(300, 100)
        self.scan_dir_button.setMinimumSize(300, 100)
        self.scan_dir_button.clicked.connect(self.scan_dir)
        self.dir_layout.addWidget(self.scan_dir_button)
        self.dir_visited = True

    def main_menu_window(self):

        if self.flag:
            self.clearLayout()
        self.flag = True

        # threads for the fuzzy hashing
        self.thread1, self.thread2, self.thread3, self.thread4 = None, None, None, None

        self.redis_virus = Redis()
        self.redis_virus.print_all()

        self.list_widget_style_sheet = """
            QListWidget {
                background-color: #333;
                border: 1px solid #ccc;
                border-radius: 5px;
                outline: none;
                margin: 5px;
                font-size: 20ע
            }
            QListWidget::item {
                border: none;
                padding: 10px;
                font: 18px;
                font-weight: 500;
            }
            QListWidget::item[role=highlight] {
                color: red;
            }

            QListWidget::item:hover {
                background-color: #555;
            }

            QListWidget::item:selected {
                background-color: #777;
            }
        """

        self.movie_label = None
        self.movie_label_ip = None
        self.delete_widgets = None
        self.fuzzy_spin = None
        self.virus_total_label = None

        self.page_layout = QVBoxLayout()
        self.btn_layout = QHBoxLayout()
        self.run_once = 0
        self.activate_btn_layout = QHBoxLayout()
        self.resize(1200, 600)

        self.listbox_view = ListBoxWidget(self)
        self.btn = QPushButton('Start Dynamic Scan', self)
        self.btn.setStyleSheet("QPushButton {background-color: #E6E6FA; color: #000080; border: 2px solid #9400D3; "
                               "font: bold 18px; min-width: 80px; padding: 6px; margin-top: 20px;} "
                               "QPushButton:hover {background-color: #D8BFD8; color: #4B0082;} QPushButton:pressed {"
                               "background-color: #DDA0DD; color: #8B008B;}")

        self.start_vm_btn = QPushButton('Start Virtual Machine', self)
        self.start_vm_btn.setStyleSheet(
            "QPushButton {background-color: #E6E6FA; color: #000080; border: 2px solid #9400D3; "
            "font: bold 18px; min-width: 80px; padding: 6px; border-bottom-left-radius: 15px; "
            "margin-top: 20px;} "
            "QPushButton:hover {background-color: #D8BFD8; color: #4B0082;} QPushButton:pressed {"
            "background-color: #DDA0DD; color: #8B008B;}")

        # self.activate_btn_layout.addWidget(self.start_vm_btn)
        # self.activate_btn_layout.addWidget(self.btn)

        self.load_for_static = QPushButton('Load for Static Analysis', self)
        self.load_for_hash = QPushButton('Load for Hash Analysis', self)

        self.static_hash_load = QHBoxLayout()
        self.static_hash_load.addWidget(self.start_vm_btn)
        self.static_hash_load.addWidget(self.btn)
        self.static_hash_load.addWidget(self.load_for_static)
        self.static_hash_load.addWidget(self.load_for_hash)

        self.load_for_static.setStyleSheet(
            "QPushButton {background-color: #E6E6FA; color: #000080; border: 2px solid #9400D3; "
            "font: bold 18px; min-width: 100px; padding: 6px; width: 100px; margin-top: 20px;} "
            "QPushButton:hover {background-color: #D8BFD8; color: #4B0082;} QPushButton:pressed {"
            "background-color: #DDA0DD; color: #8B008B;}")
        self.load_for_hash.setStyleSheet(
            "QPushButton {background-color: #E6E6FA; color: #000080; border: 2px solid #9400D3; "
            "font: bold 18px; min-width: 80px; padding: 6px; border-bottom-right-radius: 15px; "
            "margin-top: 20px;}} "
            "QPushButton:hover {background-color: #D8BFD8; color: #4B0082;} QPushButton:pressed {"
            "background-color: #DDA0DD; color: #8B008B;}")

        self.l1 = make_label("YESH SCANNER", 28)
        self.h_box_for_l1_and_dial = QHBoxLayout()
        # self.h_box_for_l1_and_dial.setAlignment(Qt.AlignCenter)
        self.h_box_for_l1_and_dial.addWidget(self.l1)

        self.dial_instance = DialWatch()
        self.dial = self.dial_instance.get_dial()
        self.h_box_for_l1_and_dial.addWidget(self.dial, alignment=Qt.AlignRight)

        # setting after moving to home screen
        if os.path.exists("virus.exe"):
            if self.redis_virus.exists(str(md5("virus.exe"))):
                self.dial_instance.setDialPercentage(int(self.redis_virus.get_key(str(md5("virus.exe")), "final_assesment", False)))
                self.dial = str(md5("virus.exe"))
                self.run_for_start = True

        self.l1.setStyleSheet("QLabel { font: bold; margin-bottom: 0px; padding: 10px; margin-left:325px;} ")

        self.start_label_explantion = QLabel("Analyse suspicious files to detect malware\n"
                                             "Automatic, Fast, User Friendly\n")
        font = QFont("Zapfino", 16)
        self.start_label_explantion.setFont(font)
        self.setStyleSheet("QLabel { margin-bottom: 20px; } ")
        self.start_label_explantion.setAlignment(Qt.AlignCenter)

        self.drag_and_drop_gif = QLabel()
        self.drag_and_drop_gif.setFixedSize(0, 20)
        self.movie_drag = QMovie("images/drag_and_drop.gif")
        self.drag_and_drop_gif.setMovie(self.movie_drag)
        self.drag_and_drop_gif.setAlignment(Qt.AlignCenter)

        self.dynamic_button = QPushButton("Dynamic Analysis")
        self.dynamic_button.setStyleSheet(
            "QPushButton {background-color: #E6E6FA; color: #000080; border: 2px solid #9400D3; "
            "font: bold 25px; min-width: 80px; margin: 5px; margin-right: 10px; margin-bottom: 10px; "
            "border-top-left-radius: 20px;} "
            "QPushButton:hover {background-color: #D8BFD8; color: #4B0082;} QPushButton:pressed {"
            "background-color: #DDA0DD; color: #8B008B;}")
        self.dynamic_button.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.dynamic_button.setFlat(True)
        self.dynamic_button.setDisabled(False)

        self.static_button = QPushButton("Static Analysis")
        self.static_button.setStyleSheet(
            "QPushButton {background-color: #E6E6FA; color: #000080; border: 2px solid #9400D3; "
            "font: bold 25px; min-width: 80px; margin: 5px; margin-bottom: 10px;} "
            "QPushButton:hover {background-color: #D8BFD8; color: #4B0082;} QPushButton:pressed {"
            "background-color: #DDA0DD; color: #8B008B;}")
        self.static_button.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.static_button.setFlat(True)

        self.hash_button = QPushButton("Hash Analysis")
        self.hash_button.setStyleSheet(
            "QPushButton {background-color: #E6E6FA; color: #000080; border: 2px solid #9400D3; "
            "font: bold 25px; min-width: 80px; margin: 2px; margin-left: 10px; margin-bottom: 10px; "
            "border-top-right-radius: 20px;} "
            "QPushButton:hover {background-color: #D8BFD8; color: #4B0082;} QPushButton:pressed {"
            "background-color: #DDA0DD; color: #8B008B;}")
        self.hash_button.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.hash_button.setFlat(True)

        # btn_layout.addItem(Qt.SpacerItem(0, 0,QSizePolicy.Expanding, Qt.QSizePolicy.Minimum))
        # self.btn_layout.addStretch(1)
        self.btn_layout.addWidget(self.dynamic_button, Qt.AlignCenter)
        self.btn_layout.addWidget(self.static_button, Qt.AlignCenter)
        self.btn_layout.addWidget(self.hash_button, Qt.AlignCenter)
        self.btn_layout.setAlignment(Qt.AlignCenter)

        self.page_layout.setAlignment(Qt.AlignCenter)
        self.page_layout.addLayout(self.h_box_for_l1_and_dial)
        self.page_layout.addWidget(self.start_label_explantion)
        self.page_layout.addLayout(self.btn_layout)
        # self.page_layout.addWidget(self.drag_and_drop_gif)
        # self.movie_drag.start()

        self.page_layout.addWidget(self.listbox_view)
        # self.page_layout.addLayout(self.activate_btn_layout)
        self.page_layout.addLayout(self.static_hash_load)
        self.page_layout.addStretch(1)
        self.page_layout.setContentsMargins(80, 20, 80, 20)

        self.dynamic_visited = False
        self.static_visited = False
        self.hash_visited = False
        self.dir_visited = False
        self.ip_visited = False
        self.settings_visited = False

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

        self.container = QGroupBox()
        # self.widget.setLayout(self.page_layout)
        self.container.setLayout(self.page_layout)

        # Scroll Area Properties
        self.scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.scroll.setWidgetResizable(True)
        self.scroll.setWidget(self.container)
        self.setCentralWidget(self.scroll)

        # # horizontal scroll area
        # self.scroll_horizontal = QScrollArea()
        # self.widget_horizontal = QWidget()
        # self.widget_horizontal.setLayout(self.page_layout)
        # self.scroll_horizontal.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        # self.scroll_horizontal.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        # self.scroll_horizontal.setWidgetResizable(True)
        # self.scroll_horizontal.setWidget(self.widget_horizontal)
        # self.setCentralWidget(self.scroll_horizontal)

        self.btn.clicked.connect(lambda: self.getSelectedItem())
        self.start_vm_btn.clicked.connect(lambda: self.activate_vm())
        self.static_button.clicked.connect(lambda: [self.static_analysis()])
        self.hash_button.clicked.connect(lambda: [self.hash_analysis()])
        self.dynamic_button.clicked.connect(lambda: [self.dynamic_analysis()])

    def python_analysis(self):
        self.clearLayout()
        self.dynamic_visited = False
        self.static_visited = False
        self.ip_visited = False
        self.hash_visited = False
        self.dir_visited = False
        self.settings_visited = False
        self.pv = PythonVirus("virus.exe")
        self.pv.log_for_winapi(self.pv.find_ctypes_calls())

        # TODO - present the python nicely, probably in a QTreeWidget

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

        self.md5_hash = str(md5("virus.exe"))
        if not self.redis_virus.exists(self.md5_hash):
            self.redis_virus.hset_dict(self.md5_hash,
                                       {"rules": pickle.dumps([0]), "packers": pickle.dumps([0]),
                                        "entropy_vs_normal": pickle.dumps([0]),
                                        "fractioned_imports_test": pickle.dumps([0]),
                                        "rick_optional_linker_test": pickle.dumps([0]),
                                        "sections_test": pickle.dumps([0]), "suspicious_!": pickle.dumps([0]),
                                        "identifies": pickle.dumps([0]), "has_passed_cpu": pickle.dumps([0]),
                                        "num_of_engines:": 0,
                                        "num_of_fuzzy_found": 0, "final_assesment": 0})

        # self.redis_virus.change_to_reg()
        # self.redis_virus.hset(self.md5_hash, "num_of_rules", pickle.dumps(["bad_rule", 5]))
        # print(pickle.loads(self.redis_virus.hgetall(self.md5_hash)[b"num_of_rules"]))
        # self.redis_virus.print_all()
        # print(int(self.redis_virus.hgetall('5fffd3e69093dc32727214ba5c8f2af5')[b'num_of_rules'].decode()) * 5)

        if Packers.programming_language(path) == "py":  # a python file
            self.py_thread = QThread()
            self.py_thread.run = self.python_analysis
            self.py_thread.start()
            return

        # if Packers.programming_language(path) is not True:  # either not exe, or not written in the languages
        #     msg = QMessageBox()
        #     msg.setIcon(QMessageBox.Warning)
        #     msg.setText("This file isn't in EXE format, please be aware of our rules and terms")
        #     msg.setWindowTitle("Warning")
        #     msg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
        #     result = msg.exec_()
        #     return

        while not os.path.exists(r"E:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\graphics"
                                 r"\virus.exe"):
            print('File does not exists')
            pass

        self.threadpool_sender = QThreadPool()
        worker = Worker(self.activate_sender)
        self.threadpool_sender.start(self.activate_sender)

    def open_list(self):
        button = self.sender()
        if "+" in button.text():
            button.setText(button.text().replace("+", "-"))
        else:
            button.setText(button.text().replace("-", "+"))
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

    def activate_sender(self):

        print("got to sender")
        s = Sender()
        for got in s.run():
            if got == 1:
                self.dynamic_button.setEnabled(True)
                return

    def start_vm(self):
        self.threadpool_vm = QThreadPool()
        worker = Worker(self.activate_vm)
        self.threadpool_vm.start(self.activate_vm)

    def create_scroll_bar(self):

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
        return scrollBar

    def static_analysis(self):

        # self.show_loading_menu()
        self.clearLayout()

        self.static_visited = True
        self.hash_visited = False
        self.dynamic_visited = False
        self.dir_visited = False
        self.ip_visited = False
        self.settings_visited = False

        # self.page_layout.addLayout(self.btn_layout)
        self.static_button.setEnabled(False)
        self.hash_button.setDisabled(False)

        self.virus_table = QTableView()
        # self.virus_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        sections = sections_entropy("virus.exe")[1:]
        sections.insert(0, ["Name", "Virtual Address", "Virtual Size", "Raw Size", "Entropy"])
        print(sections)

        model = TableModel(sections)
        self.virus_table.setModel(model)

        self.virus_table.setStyleSheet("""
        QTableView {
            font-family: sans-serif;
            font-size: 18px;
            color: #87CEFA;
            background-color: #333;
            border: 2px solid #444;
            gridline-color: #666;
        } 
        QTableView::item {
            padding: 20px;
            margin: 20px;
            min-width: 100px;
            min-height: 20px;
            font-weight: bold;
        }
        QTableView::header {
            font-size: 24px;
            font-weight: bold;
            background-color: #444;
            border: 2px solid #555;
            min-height: 20px;
        }
    """)

        # Set the column widths
        self.virus_table.setColumnWidth(4, 200)
        self.virus_table.setColumnWidth(2, 200)
        self.virus_table.setColumnWidth(1, 200)
        self.virus_table.setColumnWidth(0, 170)
        self.virus_table.setColumnWidth(3, 150)
        # basic_info.setColumnWidth(1, 620)

        # Set the row heights
        for row in range(model.rowCount()):
            self.virus_table.setRowHeight(row, 40)

        self.virus_table.setMinimumSize(100, 430)

        self.md5_hash = str(md5("virus.exe"))
        entropy_of_virus_vs_reg = entropy_vs_normal("virus.exe")
        self.redis_virus.hset(self.md5_hash, "entropy_vs_normal", pickle.dumps(entropy_of_virus_vs_reg))
        self.redis_entropy = self.redis_virus.get_key(self.md5_hash, "entropy_vs_normal", True)
        reg_entropy = self.redis_entropy.pop()
        percentage = self.dial_instance.get_percentage()
        if self.run_for_entropy == 1 and not self.run_for_start:
            if len(self.redis_entropy) >= 1:
                self.dial_instance.setDialPercentage(percentage + int(len(self.redis_entropy)))
            self.dial_instance.setDialPercentage(percentage + int(reg_entropy))
            self.redis_virus.hset(self.md5_hash, "final_assesment", percentage + int(reg_entropy))
            self.dial = self.dial_instance.get_dial()
            self.run_for_entropy = 0

        self.table_and_strings_layout = QVBoxLayout()

        self.virus_table_label = make_label("The Portable Executable Table", 24)
        self.table_and_strings_layout.addWidget(self.virus_table_label)
        self.table_and_strings_layout.addWidget(self.virus_table, 0)

        class bubbleWidget(QWidget):
            def __init__(self, text, parent=None):
                super().__init__(parent)
                self.text = text
                self.setWindowFlags(Qt.ToolTip)
                self.setAttribute(Qt.WA_TranslucentBackground)
                self.setFixedSize(400, 300)  # set the size of the bubble to be smaller
                self.setAutoFillBackground(False)  # remove black background
                self.setAttribute(Qt.WA_TransparentForMouseEvents)
                self.setStyleSheet("background-color:transparent;")

            def paintEvent(self, event):
                painter = QPainter(self)
                painter.setRenderHint(QPainter.Antialiasing)
                painter.setBrush(QColor("white"))
                painter.setPen(QColor(0, 0, 0, 0))
                painter.drawRect(QRectF(10, 10, self.width() - 20, self.height() - 20))
                painter.setPen(QPen(Qt.black))
                font = QFont("Arial", 11, QFont.Bold)
                painter.setFont(font)
                painter.drawText(QRectF(10, 10, self.width() - 20, self.height() - 20),
                                 Qt.AlignTop | Qt.AlignLeft | Qt.TextWordWrap, self.text)

        def show_bubble(item):

            item_text = item.text()
            self.bubble = bubbleWidget(item_text + "\n\n" + bubble_strings_dict[item_text])
            self.bubble.setStyleSheet("background-color:transparent;")

            pos = self.list_strings_widget.visualItemRect(item).topRight()
            pos.setX(pos.x() + 20)
            self.bubble.move(self.list_strings_widget.mapToGlobal(pos))
            self.bubble.show()

        def show_bubble_packer(item):

            item_text = item.text()
            self.bubble = bubbleWidget(item_text + "\n\n" + bubble_strings_dict[item_text])
            self.bubble.setStyleSheet("background-color:transparent;")

            pos = self.packers_widget.visualItemRect(item).topRight()
            pos.setX(pos.x() + 20)
            self.bubble.move(self.packers_widget.mapToGlobal(pos))
            self.bubble.show()

        def leaveEvent(event):
            self.bubble.hide()

        # Create a list widget and add some items to it
        self.list_strings_widget = QListWidget()
        self.list_strings_widget.setMaximumSize(450, 550)
        self.list_strings_widget.setMinimumSize(450, 550)
        # self.list_strings_widget.itemEntered.connect(show_bubble)

        # YARA
        yara_strings = YaraChecks.check_for_strings("virus.exe")
        yara_packers = YaraChecks.check_for_packer("virus.exe")

        if self.run_for_rules == 1 and not self.run_for_start:
            self.redis_virus.hset(self.md5_hash, "rules", pickle.dumps([match.rule for match in yara_strings[2]]))
            self.redis_rules = self.redis_virus.get_key(self.md5_hash, "rules", True)
            percentage = self.dial_instance.get_percentage()
            self.dial_instance.setDialPercentage(percentage + len(self.redis_rules) * 5)
            self.dial = self.dial_instance.get_dial()
            self.redis_virus.hset(self.md5_hash, "final_assesment", percentage + len(self.redis_rules) * 5)
            self.run_for_rules = 0

        if self.run_for_packers == 1 and not self.run_for_start:
            self.redis_virus.hset(self.md5_hash, "packers", pickle.dumps([match.rule for match in yara_packers]))
            self.redis_packers = self.redis_virus.get_key(self.md5_hash, "packers", True)
            percentage = self.dial_instance.get_percentage()
            self.dial_instance.setDialPercentage(percentage + int(len(self.redis_packers) * 0.5))
            self.dial = self.dial_instance.get_dial()
            self.redis_virus.hset(self.md5_hash, "final_assesment", percentage + int(len(self.redis_packers) * 0.5))
            self.run_for_packers = 0

        for dll in yara_strings[0]:
            item = QListWidgetItem(str(dll))
            item.setToolTip(bubble_strings_dict[str(dll)])
            font = item.font()
            font.setPointSize(12)
            item.setFont(font)
            color = QColor()
            color.setNamedColor("#87CEFA")
            item.setForeground((QBrush(color)))
            self.list_strings_widget.addItem(item)
            # self.list_strings_widget.setMouseTracking(True)
            # self.list_strings_widget.itemEntered.connect(show_bubble)
            # self.list_strings_widget.leaveEvent = leaveEvent
            # self.bubble = bubbleWidget(dll)
            # self.bubble.hide()

        # check for injection strings
        injection_funcs = []
        registry_strings = []
        if b'VirtualAllocEx' in yara_strings[1] and b'WriteProcessMemory' in yara_strings[1] and b'OpenProcess' in \
                yara_strings[1] and b'CreateRemoteThread' in yara_strings[1]:
            injection_funcs = [b'VirtualAllocEx', b'WriteProcessMemory', b'OpenProcess', b'CreateRemoteThread']

        # check for registry suspicious keys
        if b'SOFTWARE\\Policies\\Microsoft\\Windows Defender' in yara_strings[
            1] and b'Software\\Microsoft\\Windows\\CurrentVersion\\Run' in yara_strings[1]:
            registry_strings = [b'SOFTWARE\\Policies\\Microsoft\\Windows Defender',
                                b'Software\\Microsoft\\Windows\\CurrentVersion\\Run']

        for string in yara_strings[1]:

            item = QListWidgetItem(str(string.decode()))
            if string in injection_funcs or string in registry_strings:
                item.setForeground(QBrush(QColor('red')))
            else:
                color = QColor()
                color.setNamedColor("#87CEFA")
                item.setForeground((QBrush(color)))

            item.setToolTip(bubble_strings_dict[string.decode()])
            font = item.font()
            font.setPointSize(12)
            item.setFont(font)

            self.list_strings_widget.addItem(item)
            # self.list_strings_widget.setMouseTracking(True)
            # self.list_strings_widget.itemEntered.connect(show_bubble)
            # self.bubble = bubbleWidget(str(string.decode()))
            # self.bubble.hide()

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
        self.list_strings_widget.setStyleSheet(self.list_widget_style_sheet)

        self.strings_label = make_label("Suspicious Strings", 24)
        self.list_strings_widget.setVerticalScrollBar(scrollBar)
        self.reg_strings_box = QVBoxLayout()
        self.reg_strings_box.addWidget(self.strings_label)
        self.reg_strings_box.addWidget(self.list_strings_widget)
        # self.table_and_strings_layout.addWidget(self.strings_label)
        # self.table_and_strings_layout.addWidget(self.list_strings_widget)

        # sys internals
        self.strings_box = QHBoxLayout()

        self.sys_internals_strings_label = make_label("Additional Strings", 24)

        s = SysInternals()
        self.sys_internals_strings_list = QListWidget()
        self.sys_internals_strings_list.setVerticalScrollBar(self.create_scroll_bar())
        self.sys_internals_strings_list.setHorizontalScrollBar(self.create_scroll_bar())
        self.sys_internals_strings_list.setMaximumSize(475, 550)
        self.sys_internals_strings_list.setMinimumSize(475, 550)
        self.sys_internals_strings_list.setStyleSheet(self.list_widget_style_sheet)

        for string in s.run_strings():

            if string != "":
                item = QListWidgetItem(str(string))
                font = item.font()
                font.setPointSize(12)
                item.setFont(font)
                color = QColor()
                color.setNamedColor("#87CEFA")
                item.setForeground((QBrush(color)))
                self.sys_internals_strings_list.addItem(item)

        self.sys_internals_strings_box = QVBoxLayout()
        self.sys_internals_strings_box.addWidget(self.sys_internals_strings_label)
        self.sys_internals_strings_box.addWidget(self.sys_internals_strings_list)

        self.strings_box.addLayout(self.reg_strings_box)
        self.strings_box.addLayout(self.sys_internals_strings_box)
        self.table_and_strings_layout.addLayout(self.strings_box)

        self.packers_label = make_label("Packers And Protectors", 24)
        self.packers_widget = QListWidget()
        self.packers_widget.setMaximumSize(400, 300)
        # self.packers_widget.itemEntered.connect(show_bubble)

        scrollBarPackers = QScrollBar()
        scrollBarPackers.setOrientation(Qt.Vertical)
        scrollBarPackers.setMinimum(0)
        scrollBarPackers.setMaximum(100)
        scrollBarPackers.setSingleStep(1)
        scrollBarPackers.setPageStep(10)
        scrollBarPackers.setValue(50)
        scrollBarPackers.setStyleSheet(self.scrollBar_stylesheet)

        for packer, tag in yara_packers.items():
            item = QListWidgetItem(str(packer))
            item.setToolTip(bubble_strings_dict[str(packer)])
            font = item.font()
            font.setPointSize(12)
            item.setFont(font)
            self.packers_widget.addItem(item)
            # self.packers_widget.setMouseTracking(True)
            # self.packers_widget.itemEntered.connect(show_bubble_packer)
            # self.packers_widget.leaveEvent = leaveEvent
            # self.bubble = bubbleWidget(packer)
            # self.bubble.hide()

        self.packers_widget.setMinimumSize(450, 200)
        self.packers_widget.setStyleSheet("""
            QListWidget {
                background-color: #333;
                border: 1px solid #ccc;
                border-radius: 5px;
                outline: none;
                margin: 5px;
                font-size: 20ע
            }
            QListWidget::item {
                border: none;
                padding: 10px;
                font: 18px;
                font-weight: 500;
                color: #87CEFA;
            }
            QListWidget::item[role=highlight] {
                color: red;
            }

            QListWidget::item:hover {
                background-color: #555;
            }
            """)
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

        self.tree_imports = QTreeView()
        self.tree_imports.setMaximumSize(200, 500)
        self.tree_imports.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tree_imports.setStyleSheet("""
        QTreeView {
            font-family: sans-serif;
            font-size: 14px;
            color: #87CEFA;
            background-color: #333;
            border: 2px solid #444;
            gridline-color: #666;
            margin-top: 10px;
            margin-bottom: 10px;
        }

        QTreeView::branch:has-siblings:!adjoins-item {
            border-image: url(images/vline.png) 0;
        }

        QTreeView::branch:has-siblings:adjoins-item {
            border-image: url(images/branch-more.png) 0;
        }

        QTreeView::branch:!has-children:!has-siblings:adjoins-item {
            border-image: url(images/branch-end.png) 0;
        }

        QTreeView::branch:has-children:!has-siblings:closed,
        QTreeView::branch:closed:has-children:has-siblings {
                border-image: none;
                image: url(images/branch-closed.png);
        }

        QTreeView::branch:open:has-children:!has-siblings,
        QTreeView::branch:open:has-children:has-siblings  {
                border-image: none;
                image: url(images/branch-open.png);
        }

        QTreeView::branch:selected {
            color: white;
        }

        QTreeView::item {
            padding: 5px;
            margin: 1px;
        }

        QTreeView::item:hover {
            background-color: #555;
        }

        QTreeView::item:selected {
            background-color: #777;
        }

        QTableWidget::item:selected:active {
            background-color: #999;
        }

        QTableWidget::item:selected:!active {
            background-color: #red;
        }""")

        root = QStandardItem("See Imports")
        for library, imps in dlls.items():

            lib = library[0]
            dll = QStandardItem(lib)
            for imp in imps:
                dll.appendRow(QStandardItem(imp))

            root.appendRow(dll)

        model = QStandardItemModel()
        model.appendRow(root)
        self.tree_imports.setModel(model)
        self.tree_imports.setMinimumSize(350, 300)
        self.table_and_strings_layout.addWidget(self.tree_imports)

        # PE TESTS
        self.pe_tests_label = make_label("PE examination", 24)
        self.table_and_strings_layout.addWidget(self.pe_tests_label)

        self.page_layout.addLayout(self.table_and_strings_layout)
        self.static_visited = True
        self.h_box_for_groupbox = QHBoxLayout()

        fractioned = check_for_fractioned_imports(dlls)
        self.redis_virus.hset(self.md5_hash, "fractioned_imports_test", pickle.dumps(fractioned))

        if self.run_for_fractioned == 1 and not self.run_for_start:
            self.redis_fractioned = self.redis_virus.get_key(self.md5_hash, "fractioned_imports_test", True)
            percentage = self.dial_instance.get_percentage()
            self.dial_instance.setDialPercentage(percentage + int(len(fractioned) * 3))
            self.dial = self.dial_instance.get_dial()
            self.redis_virus.hset(self.md5_hash, "final_assesment", percentage + int(len(fractioned) * 3))
            self.run_for_fractioned = 0

        self.fractioned = QGroupBox("Fractioned Imports")
        title = QLabel("Fractioned Imports  <img src='images/info-32.png' width='20' height='20'>")
        title.setStyleSheet(
            "QLabel {margin: 0px; margin-left: 5px;}")
        title.setToolTip("Another virus-typical behaviour is the introduction fractionated imports.\n Generally all "
                         "imports are placed in one section, but if they are spread over different sections, "
                         "they are called fractionated. \nSome viruses add imports deliberately to make sure they can "
                         "use certain system APIs. \nThe fractioning is an unintended side-effect from placing the "
                         "imports at a virus-convenient location that is usually not near the imports of the original "
                         "file.")
        self.fractioned.setTitle("")
        self.fractioned.setMinimumSize(300, 200)
        self.fractioned.setMaximumSize(400, 250)
        self.v_box_for_fractioned = QVBoxLayout()
        self.v_box_for_fractioned.addWidget(title)
        self.list_widget_for_fractioned = QListWidget()
        self.list_widget_for_fractioned.setVerticalScrollBar(self.create_scroll_bar())
        self.list_widget_for_fractioned.setMaximumSize(300, 125)
        self.list_widget_for_fractioned.setMinimumSize(300, 125)
        self.list_widget_for_fractioned.addItems(fractioned)
        self.v_box_for_fractioned.addWidget(self.list_widget_for_fractioned)
        self.fractioned.setLayout(self.v_box_for_fractioned)

        # pe linker
        result = str(pe_scan.linker_test()).replace("result.", "")
        self.redis_virus.hset(self.md5_hash, "rick_optional_linker_test", pickle.dumps([result]))
        self.redis_invalid = self.redis_virus.get_key(self.md5_hash, "rick_optional_linker_test", True)
        if self.redis_invalid == ['INVALID']:
            if self.run_for_linker == 1 and not self.run_for_start:
                percentage = self.dial_instance.get_percentage()
                self.dial_instance.setDialPercentage(percentage + 5)
                self.dial = self.dial_instance.get_dial()
                self.redis_virus.hset(self.md5_hash, "final_assesment", percentage + 5)
                self.run_for_linker = 0

        self.pe_linker = QGroupBox("PE Linker")
        title_linker = QLabel("PE Linker  <img src='images/info-32.png' width='20' height='20'>")
        title_linker.setStyleSheet(
            "QLabel {margin: 0px; margin-left: 0px; margin-bottom: 30px; }")
        title_linker.setToolTip("""Checks that the Rich and PE header linker versions do not conflict. Certain Rich Header ProdIDs correspond to
linker versions Although they are undocumented, we have used prior research as well as our own to determine
many of them There are likely more linker version ProdIDs that we have not identified If the linker versions
conflict, this function returns INVALID
This indicates that the Rich header or PE header has been modified
If the Rich Header is present, a linker mismatch between the Rich Header linker and Optional Header linker
version indicates manipulation of the headers. Since the Rich Header is a means to attribute samples to
threat actors, malware authors might get the idea to swap the DOS Stub and Rich Header with those of other
threat actor's samples""")
        self.pe_linker.setTitle("")
        self.pe_linker.setMaximumSize(300, 200)
        self.v_box_for_pe_linker = QVBoxLayout()
        self.v_box_for_pe_linker.addWidget(title_linker)
        self.label_for_pe_linker = QLabel(result)
        if result != "Valid":
            self.label_for_pe_linker.setStyleSheet("QLabel { color: red; margin-bottom: 30px; margin-top:0px;}")
        self.v_box_for_pe_linker.addWidget(self.label_for_pe_linker)
        self.pe_linker.setLayout(self.v_box_for_pe_linker)

        # pe scan sections
        sections = pe_scan.scan_sections()
        if self.run_for_sections == 1 and not self.run_for_start:
            self.redis_virus.hset(self.md5_hash, "sections_test", pickle.dumps(sections))
            self.redis_sections = self.redis_virus.get_key(self.md5_hash, "sections_test", True)
            percentage = self.dial_instance.get_percentage()
            self.dial_instance.setDialPercentage(percentage + int(len(self.redis_sections) * 0.5))
            self.dial = self.dial_instance.get_dial()
            self.redis_virus.hset(self.md5_hash, "final_assesment", percentage + int(len(self.redis_sections) * 0.5))
            self.run_for_sections = 0

        self.suspicious_imports = QGroupBox("Suspicious Imports")
        title = QLabel("Suspicious Imports  <img src='images/info-32.png' width='20' height='20'>")
        title.setStyleSheet(
            "QLabel { margin-top: 10px; margin-left: 5px; margin-bottom: 10px;}")
        title.setToolTip("""Patches in the Section Table
A prominent red flag for non-packed files is the presence of write and execute characteristics in a section
Most of the time write and execute characteristics do not appear together in a section in non-packed files,
whereas it is rather typical for packed files.
The presence of both means the code itself can be changed dynamically
        """)
        self.suspicious_imports.setTitle("")
        self.suspicious_imports.setMinimumSize(200, 200)
        self.suspicious_imports.setMaximumSize(400, 250)
        self.v_box_for_suspicious_imports = QVBoxLayout()
        self.v_box_for_suspicious_imports.addWidget(title)
        self.list_widget_for_suspicious_imports = QListWidget()
        self.list_widget_for_suspicious_imports.setVerticalScrollBar(self.create_scroll_bar())
        self.list_widget_for_suspicious_imports.setMaximumSize(300, 125)
        self.list_widget_for_suspicious_imports.setMinimumSize(300, 125)
        self.list_widget_for_suspicious_imports.addItems(sections)
        self.v_box_for_suspicious_imports.addWidget(self.list_widget_for_suspicious_imports)
        self.suspicious_imports.setLayout(self.v_box_for_suspicious_imports)

        groupbox_style_sheet = """
                QGroupBox {
                    background-color: #333;
                    border: 1px solid #ccc;
                    border-radius: 5px;
                    outline: none;
                    margin: 5px;
                    color: #87CEFA; 
                    font-size: 20px;
                }

                QGroupBox::title {
                    subcontrol-origin: margin;
                    margin-bottom: 90px;
                    margin: 10px;
                    subcontrol-position: top left;
                    padding: 10px 20px;
                    font-size: 15px;
                    font-weight: 500;
                    color: #87CEFA;
                }

                QLabel {
                    color: #87CEFA; 
                    font-size: 20px;
                    font-weight: 500;
                    justify-content: center;
                    text-alignment: center;
                    margin-left: 15px;
                }

                QListWidget {
                    background-color: #333;
                    border: 1px solid #ccc;
                    border-radius: 5px;
                    outline: none;
                    margin: 10px;
                    color: #87CEFA; 
                    font-size: 16px;
                    font-weight: 500;
                    margin-bottom: 40px;
                    margin-top: 5px;
                }

                QListWidget::item {
                    border: none;
                    color: red;
                    padding: 5px;
                    font-size: 16px;
                    font-weight: 500; 
                }

                QListWidget::item:hover {
                    background-color: #555;
                }

                QListWidget::item:selected {
                    background-color: #777;
                }
            """

        self.fractioned.setStyleSheet(groupbox_style_sheet)
        self.suspicious_imports.setStyleSheet(groupbox_style_sheet)
        self.pe_linker.setStyleSheet(groupbox_style_sheet)

        self.h_box_for_groupbox.addWidget(self.fractioned)
        self.h_box_for_groupbox.addWidget(self.suspicious_imports)
        self.h_box_for_groupbox.addWidget(self.pe_linker)
        #
        self.table_and_strings_layout.addLayout(self.h_box_for_groupbox)

    def activate_vt_scan_dir(self):

        for path in VTScan.scan_directory(self.dir, self.progress_bar_dir):
            try:
                if path == "stop":
                    self.movie_dir.stop()
                    self.description_for_search.setText("All Done !!")
                    break
                self.suspicious_paths.addItem(str(path))
            except SystemExit as e:
                if e.code == -1073741819:
                    print("got this system exit")

    def activate_vt_scan_ip(self):

        mutex = threading.Semaphore(1)

        for block_ip in VTScan.scan_for_suspicious_cache(self.progress_bar_ip, mutex):

            if block_ip == "stop":
                self.movie_ip.stop()
                self.description_for_ip_analysis.setText("All Done !!")
                continue

            if isinstance(block_ip, list):
                print("got here ", block_ip)
                result = subprocess.run(['python', 'use_for_block.py'] + block_ip, capture_output=True, text=True)
                continue

            if block_ip == "1.0.0.127":
                continue

            item = QListWidgetItem(str(block_ip))
            # item.setFlags(item.flags() & ~Qt.ItemIsSelectable)
            self.suspicious_ip.addItem(item)

    def scan_dir(self):

        self.dir = str(QFileDialog.getExistingDirectory(self, "Select Directory"))
        self.threadpool_vt = QThread()
        self.show_movie()

        self.suspicious_paths = QListWidget()
        self.suspicious_paths.setVerticalScrollBar(self.create_scroll_bar())
        self.suspicious_paths.setStyleSheet("""
            QListWidget {
                background-color: #333;
                border: 1px solid #ccc;
                border-radius: 5px;
                outline: none;
                margin: 5px;
                font-size: 20ע
            }
            QListWidget::item {
                border: none;
                padding: 10px;
                font: 18px;
                font-weight: 500;
                color: #87CEFA;
            }
            QListWidget::item[role=highlight] {
                color: red;
            }

            QListWidget::item:hover {
                background-color: #555;
            }
            """)

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
        self.dir_layout.insertLayout(self.dir_layout.indexOf(self.description_progress) + 1, self.movie_list)

        self.threadpool_vt.run = self.activate_vt_scan_dir
        self.threadpool_vt.start()

    def show_movie(self):

        if self.show_label == 1:
            self.description_progress = QHBoxLayout()
            self.description_for_search = make_label("If a file was found malicious by more than 5 engines\n"
                                                     "it will be shown on the screen to your right", 15)

            self.progress_bar_dir = QProgressBar()
            self.progress_bar_dir.setRange(0, 100)
            self.progress_bar_dir.setMaximumSize(350, 20)
            self.progress_bar_dir.setMinimumSize(300, 20)
            self.progress_bar_dir.setStyleSheet("QProgressBar { font: bold 18px; } ")

            palette = self.progress_bar_dir.palette()
            palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(124, 252, 0))
            self.progress_bar_dir.setPalette(palette)

            self.description_progress.addWidget(self.description_for_search)
            self.description_progress.addWidget(self.progress_bar_dir)
            self.dir_layout.insertLayout(self.dir_layout.indexOf(self.scan_dir_button) + 1,
                                         self.description_progress)

            # Create the QLabel
            self.movie_label = QLabel()
            self.movie_list = QHBoxLayout()

            # Set the GIF image as the QLabel's movie
            self.movie_dir = QMovie('file_scan.gif')
            self.movie_label.setMovie(self.movie_dir)

            # Start the movie
            self.movie_dir.start()
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
        # self.hash_layout.insertLayout(self.hash_layout.indexOf(self.ip_analysis_label), self.fuzzy_spin)
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
                r = Redis()
                md5_hash = md5("virus.exe")
                change_spin_counter(spin_box, r, md5_hash)

        class WaitThread(QThread):
            def run(self):
                QThreadPool.globalInstance().waitForDone()

        # create and start the first thread
        self.thread1 = QThread()
        self.thread1.run = ThreadTask_49().run
        self.thread1.start()

        # create and start the first thread
        self.thread2 = QThread()
        self.thread2.run = ThreadTask_79().run
        self.thread2.start()

        # create and start the first thread
        self.thread3 = QThread()
        self.thread3.run = ThreadTask_label().run
        self.thread3.start()

        self.thread4 = QThread()
        self.thread4.run = ThreadTask_Spin().run
        self.thread4.start()

        # create the wait thread and start it in a separate thread
        # wait_thread = WaitThread()
        # wait_thread.start()

    def ip_analysis(self):

        if self.show_analysis_label == 1:
            self.description_progress_ip = QHBoxLayout()

            self.progress_bar_ip = QProgressBar()
            self.progress_bar_ip = QProgressBar()
            self.progress_bar_ip.setRange(0, 100)
            self.progress_bar_ip.setMaximumSize(350, 20)
            self.progress_bar_ip.setMinimumSize(300, 20)
            self.progress_bar_ip.setStyleSheet("QProgressBar { font: bold 18px; } ")

            palette = self.progress_bar_ip.palette()
            palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(124, 252, 0))
            self.progress_bar_ip.setPalette(palette)

            self.description_for_ip_analysis = make_label(
                "If a website was found malicious by more than 5 engines\n"
                "it will be shown on the list to your right\n"
                "And you will be blocked from using it", 15)

            self.description_progress_ip.addWidget(self.description_for_ip_analysis)
            self.description_progress_ip.addWidget(self.progress_bar_ip)
            self.ip_layout.addLayout(self.description_progress_ip)

            # Create the QLabel
            self.movie_label_ip = QLabel()
            self.movie_list_ip = QHBoxLayout()

            # Set the GIF image as the QLabel's movie
            self.movie_ip = QMovie('file_scan.gif')
            self.movie_label_ip.setMovie(self.movie_ip)

            # Start the movie
            self.movie_ip.start()
            self.movie_list_ip.addWidget(self.movie_label_ip)
            self.show_analysis_label = 0

            self.ip_thread = QThread()
            self.ip_thread.run = self.activate_vt_scan_ip

            self.suspicious_ip = QListWidget()
            self.suspicious_ip.setVerticalScrollBar(self.create_scroll_bar())
            self.suspicious_ip.setStyleSheet("""
            QListWidget {
                background-color: #333;
                border: 1px solid #ccc;
                border-radius: 5px;
                outline: none;
                margin: 5px;
                font-size: 20ע
            }
            QListWidget::item {
                border: none;
                padding: 10px;
                font: 18px;
                font-weight: 500;
                color: #87CEFA;
            }
            QListWidget::item[role=highlight] {
                color: red;
            }

            QListWidget::item:hover {
                background-color: #555;
            }

            QListWidget::item:selected {
                background-color: #777;
            }
        """)
            self.suspicious_ip.setMaximumSize(350, 350)
            self.movie_list_ip.addWidget(self.suspicious_ip)
            self.ip_layout.addLayout(self.movie_list_ip)
            self.ip_thread.start()
            self.ip_visited = True

    def quarantine(self):

        password_to_lock = "1233"
        new_file_path = Quarantine.quarantine_file("virus.exe", "QURANTINE", password_to_lock)

    def hash_analysis(self):

        self.clearLayout()
        # self.show_loading_menu()
        self.static_visited = False
        self.dynamic_visited = False
        self.dir_visited = False
        self.ip_visited = False
        self.settings_visited = False

        self.hash_button.setDisabled(True)
        self.hash_layout = QVBoxLayout()
        self.engine_tree = QTreeWidget()
        self.engine_tree.setHeaderLabels(['Name', 'Version', 'Category', 'Result', 'Method', 'Update'])

        md5_hash = md5("virus.exe")
        self.md5_hash = md5_hash
        sha_256_hash = sha_256("virus.exe")
        entropy_of_file = entropy_for_file("virus.exe")
        vtscan = VTScan()

        show_tree = True
        engines, malicious, undetected = vtscan.info(md5_hash)

        if self.run_for_engines == 1 and not self.run_for_start:
            self.redis_virus.hset(self.md5_hash, "num_of_engines", malicious)
            self.redis_engines = self.redis_virus.get_key(self.md5_hash, "num_of_engines", False)
            percentage = self.dial_instance.get_percentage()
            self.dial_instance.setDialPercentage(percentage + int(int(self.redis_engines) / 3))
            self.dial = self.dial_instance.get_dial()
            self.redis_virus.hset(self.md5_hash, "final_assesment", percentage + int(int(self.redis_engines) / 3))
            self.run_for_engines = 0

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

            # Set the column widths
            self.basic_info.setColumnWidth(0, 300)
            self.basic_info.setColumnWidth(1, 620)

            # Set the row heights
            for row in range(model.rowCount()):
                self.basic_info.setRowHeight(row, 35)

            # Set the style sheet and disable editing
            style_sheet = """
                QTableView {
                    font-family: sans-serif;
                    font-size: 18px;
                    color: #87CEFA;
                    background-color: #333;
                    border: 2px solid #444;
                    gridline-color: #666;
                } 
                QTableView::item {
                    padding: 20px;
                    margin: 20px;
                    min-width: 100px;
                    min-height: 20px;
                    font-weight: bold;
                }
                QTableView::header {
                    font-size: 24px;
                    font-weight: bold;
                    background-color: #444;
                    border: 2px solid #555;
                    min-height: 20px;
                }
            """

            self.basic_info.setStyleSheet(style_sheet)
            self.basic_info.setEditTriggers(QTableView.NoEditTriggers)

            # Allow the cells to be resized using the mouse
            self.basic_info.horizontalHeader().setSectionsMovable(True)
            self.basic_info.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
            self.basic_info.setMinimumSize(480, 240)
            self.hash_layout.addWidget(self.basic_info)

            self.virus_total_label = make_label("Virus Total Engine Results", 24)
            self.hash_layout.addWidget(self.virus_total_label)
            self.engine_tree.setVerticalScrollBar(self.create_scroll_bar())

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
                    color: #87CEFA; 
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
            font = QFont("Zapfino", 18, QFont.Bold, True)
            label.setFont(font)

            # Add some padding to the label
            label.setStyleSheet("QLabel { padding: 20px; }")
            self.hash_layout.addWidget(label)

        self.page_layout.addLayout(self.hash_layout)

        # self.scan_dir_label = make_label("Directory Analysis", 24)
        # self.hash_layout.addWidget(self.scan_dir_label)

        # Set the style sheet
        scan_dir_style_sheet = """
            QPushButton {
                background-color: #E7E7FA;
                color: #000080;
                border: 2px solid #9400D3;
                font: bold 25px;
                min-width: 80px;
                margin: 5px;
                margin-bottom: 10px;
                padding: 10px;
            }

            QPushButton:hover {
                background-color: #D8BFD8;
                color: #4B0082;
            }

            QPushButton:pressed {
                background-color: #DDA0DD;
                color: #8B008B;
            }
        """

        self.fuzzy_hash_label = make_label("Fuzzy Hashing Analysis", 24)
        self.fuzzy_hash_button = QPushButton("Scan Virus With Fuzzy Hashing")
        self.fuzzy_hash_button.setStyleSheet(scan_dir_style_sheet)
        self.fuzzy_hash_button.setMaximumSize(550, 350)
        self.hash_layout.addWidget(self.fuzzy_hash_label)
        self.hash_layout.addWidget(self.fuzzy_hash_button)

        self.fuzzy_hash_button.clicked.connect(self.fuzzy_scanning)

        self.hash_visited = True

    def dynamic_analysis(self):

        self.clearLayout()
        self.static_visited = False
        self.hash_visited = False
        self.dynamic_visited = True
        self.dir_visited = False
        self.ip_visited = False
        self.settings_visited = False
        self.dynamic_layout = QVBoxLayout()
        self.page_layout.addLayout(self.dynamic_layout)
        self.md5_hash = str(md5("virus.exe"))

        class OverlayWindow(QMainWindow):
            def __init__(self, function, functions_list):
                super().__init__()
                self.function = function
                self.function_list = functions_list
                self.initUI()

            def initUI(self):

                self.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.WindowStaysOnTopHint)

                # self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
                self.new_func_list = []
                calls = {1: "First call", 2: "Second call", 3: "Third call", 4: "4th call", 5: "5th call",
                         6: "6th call", 7: "7th call", 8: "8th call", 9: "9th call", 10: "10th call", 11: "11th call",
                         12: "12th call", 13: "13th call", 14: "14th call", 15: "15th call", 16: "16th call",
                         17: "17th call", 18: "18th call", 19: "19th call", 20: "20th call"}
                for func in self.function_list:
                    for line in [line for line in func.split("\n") if line != ""]:
                        if self.function == line.replace("-", "").replace("intercepted call to ", ""):
                            self.new_func_list.append(func)
                        break

                self.dynamic_analysis_layout = QVBoxLayout()
                show_func_once = 1
                func_index = 2
                for function in self.new_func_list:

                    # frame_for_function = QFrame()
                    # frame_for_function.setFrameShape(QFrame.Box)
                    # frame_for_function.setStyleSheet("border: 4px solid purple; margin: 10px; border-radius: 25px;")
                    #
                    # # Get the width of the screen
                    # screen_width = QMainWindow().width()
                    #
                    # # Set the maximum width of the QFrame to the width of the screen
                    # frame_for_function.setMinimumSize(screen_width, 600)
                    #
                    # v_box_for_func = QVBoxLayout(frame_for_function)
                    # v_box_for_func.setContentsMargins(0, 0, 0, 0)
                    #
                    # func = 0
                    # for line in [line for line in function.split("\n") if line != ""]:
                    #     if "-" in line:
                    #         line = line.replace("-", "").replace("intercepted call to ", "")
                    #
                    #     if "Done" in line:
                    #         continue
                    #
                    #     if func == 0:
                    #         func_head_label = QLabel(line)
                    #         func_head_label.setFont(QFont("Zapfino", 24))
                    #         func_head_label.setStyleSheet("color: {}; border: none;".format(light_purple.name()))
                    #         func_head_label.setFrameShape(QFrame.NoFrame)
                    #         v_box_for_func.addWidget(func_head_label)
                    #         func = 1
                    #         continue
                    #
                    #     func_label = QLabel(line)
                    #     func_label.setWordWrap(True)
                    #     func_label.setFont(QFont("Zapfino", 12))
                    #     func_label.setStyleSheet("color: {}; border: none;".format(light_purple.name()))
                    #     # func_label.setFrameShape(QFrame.NoFrame)
                    #     v_box_for_func.addWidget(func_label)
                    #
                    # self.dynamic_analysis_layout.addWidget(frame_for_function)

                    # Create the QTableView
                    self.func_info = QTableView()
                    data = []
                    alerts = []
                    func = 0
                    for line in [line for line in function.split("\n") if line != ""]:
                        if "-" in line:
                            line = line.replace("-", "").replace("intercepted call to ", "")

                        if "Done" in line or "Time difference" in line or "The number of times" in line or 'current cpu usage' in line:
                            continue

                        # alert
                        if "!" in line and "EXE" in line or "Has passed" in line:
                            alerts.append(line)
                            continue

                        if func == 0:
                            if show_func_once == 1:
                                func_head_label = QLabel(line)
                                func_head_label.setFont(QFont("Zapfino", 24))
                                func_head_label.setStyleSheet("color: #1E90FF; border: none; margin:5px;")
                                self.dynamic_analysis_layout.addWidget(func_head_label)
                                func = 1
                                show_func_once = 0
                                continue
                            else:
                                func_head_label = QLabel(calls[func_index])
                                func_index += 1

                                func_head_label.setFont(QFont("Zapfino", 16))
                                func_head_label.setStyleSheet("color: #87CEFA; border: none; margin:5px;")
                                self.dynamic_analysis_layout.addWidget(func_head_label)
                                func = 1
                                continue

                        parts = line.rsplit(" ", 1)
                        parts[0] = parts[0].replace("The", "").strip()
                        data.append(parts)

                    for alert in alerts:
                        label_alert = QLabel(alert)
                        label_alert.setStyleSheet("QLabel {color: red; margin: 10px; font: bold 18px;}")
                        self.dynamic_analysis_layout.addWidget(label_alert)

                    # Set the data
                    model = TableModel(data)
                    self.func_info.setModel(model)

                    # Set the column widths
                    self.func_info.setColumnWidth(0, 650)
                    self.func_info.setColumnWidth(1, 300)

                    # Set the row heights
                    for row in range(model.rowCount()):
                        self.func_info.setRowHeight(row, 35)

                    # Set the style sheet and disable editing
                    style_sheet = """
                        QTableView {
                            font-family: sans-serif;
                            font-size: 18px;
                            margin: 10px;
                            color: #87CEFA;
                            background-color: #333;
                            border: 2px solid #444;
                            gridline-color: #666;
                        }
                        QTableView::item {
                            padding: 20px;
                            margin: 20px;
                            min-width: 100px;
                            min-height: 20px;
                            font-weight: bold;
                        }
                        QTableView::header {
                            font-size: 24px;
                            font-weight: bold;
                            background-color: #444;
                            border: 2px solid #555;
                            min-height: 20px;
                        }
                    """

                    self.func_info.setStyleSheet(style_sheet)
                    self.func_info.setEditTriggers(QTableView.NoEditTriggers)

                    # Allow the cells to be resized using the mouse
                    self.func_info.horizontalHeader().setSectionsMovable(True)
                    self.func_info.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
                    # self.func_info.setMaximumSize(480, 240)
                    self.func_info.resizeColumnsToContents()
                    self.func_info.resizeRowsToContents()
                    self.func_info.setMinimumSize(0, self.func_info.sizeHint().height() * len(data[0]))
                    self.dynamic_analysis_layout.addWidget(self.func_info)

                central_widget = QWidget(self)
                central_widget.setLayout(self.dynamic_analysis_layout)
                self.setCentralWidget(central_widget)
                self.resize(1100, 500)
                # self.setLayout(self.dynamic_analysis_layout)

                self.scroll = QScrollArea()  # Scroll Area which contains the widgets, set as the centralWidget
                self.widget = QWidget()  # Widget that contains the collection of Vertical Box
                self.scroll.setStyleSheet("""
                QScrollArea {
                  boarder-radius: 20px;
                  background-color: black;
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

                self.container = QGroupBox()
                # self.widget.setLayout(self.page_layout)
                self.container.setLayout(self.dynamic_analysis_layout)

                # Scroll Area Properties
                self.scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
                self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
                self.scroll.setWidgetResizable(True)
                self.scroll.setWidget(self.container)
                self.setCentralWidget(self.scroll)

                close_button = QPushButton('X', self.container)
                close_button.setFixedSize(30, 30)
                close_button.clicked.connect(self.close)

                self.show()

            def mousePressEvent(self, event):
                self.offset = event.pos()

            def mouseMoveEvent(self, event):
                x = event.globalX()
                y = event.globalY()
                x_w = self.offset.x()
                y_w = self.offset.y()
                self.move(x - x_w, y - y_w)

        self.start_dynamic = make_label("Function Analysis", 20)
        self.start_dynamic.setText("Function Analysis  <img src='images/info-button.png' width='20' height='20'>")
        self.start_dynamic.setToolTip("Function that are red colored are shown as an alert")
        self.dynamic_layout.addWidget(self.start_dynamic)

        if os.path.exists("LOG.txt"):
            with open("LOG.txt", "r") as f:
                log_content = f.read()

                print(log_content.count("suspicious"))

        else:
            print("Could not find log")
            return

        def on_button_clicked(winapi_function):
            self.overlay = OverlayWindow(winapi_function, log_content.split("\n\n\n\n\n\n\n"))
            return

        # Creating a light shade of purple color
        light_purple = QColor(255, 153, 255, 180)

        self.grid_button_layout = QGridLayout()
        self.winapi_functions = []
        for function in log_content.split("\n\n\n\n\n\n\n"):
            for line in [line for line in function.split("\n") if line != ""]:
                func = line.replace("-", "").replace("intercepted call to ", "")
                self.winapi_functions.append(func)
                break

        self.delete_funcs = []
        suspect_functions = []
        identified_functions = []
        has_passed_cpu_functions = []

        self.tree_functions = QTreeWidget()
        self.tree_functions.setMinimumSize(500, 500)
        self.tree_functions.setStyleSheet("""
        QTreeView {
            font-family: sans-serif;
            font-size: 14px;
            color: #87CEFA;
            background-color: #333;
            border: 2px solid #444;
            gridline-color: #666;
            margin-top: 10px;
            margin-bottom: 10px;
        }

        QTreeView::branch:has-siblings:!adjoins-item {
            border-image: url(images/vline.png) 0;
        }

        QTreeView::branch:has-siblings:adjoins-item {
            border-image: url(images/branch-more.png) 0;
        }

        QTreeView::branch:!has-children:!has-siblings:adjoins-item {
            border-image: url(images/branch-end.png) 0;
        }

        QTreeView::branch:has-children:!has-siblings:closed,
        QTreeView::branch:closed:has-children:has-siblings {
                border-image: none;
                image: url(images/branch-closed.png);
        }

        QTreeView::branch:open:has-children:!has-siblings,
        QTreeView::branch:open:has-children:has-siblings  {
                border-image: none;
                image: url(images/branch-open.png);
        }

        QTreeView::branch:selected {
            color: white;
        }

        QTreeView::item {
            padding: 5px;
            margin: 1px;
        }

        QTreeView::item:hover {
            background-color: #555;
        }

        QTreeView::item:selected {
            background-color: #777;
        }

        QTableWidget::item:selected:active {
            background-color: #999;
        }

        QTableWidget::item:selected:!active {
            background-color: #red;
        }""")

        self.tree_functions.setHeaderLabel("Logged Functions")
        self.data_for_function = dict({})  # index, data

        def handle_item_click(item):
            if item.childCount() == 0 and not item.parent():
                func_data = self.data_for_function[self.tree_functions.indexOfTopLevelItem(item)]

                alerts = []
                data = []
                for line in [line for line in func_data.split("\n") if line != ""]:

                    if "-" in line:

                        line = line.replace("-", "")
                        if "IDENTIFIED" in line:
                            alerts.append(line)

                        continue

                    if "Done" in line or "Time difference" in line or "The number of times" in line or 'current cpu usage' in line:
                        continue

                    # alert
                    if "!" in line and "EXE" in line or "Has passed" in line:
                        alerts.append(line)
                        continue

                    data.append(line)

                for alert in alerts:
                    info_item = QTreeWidgetItem(item, [alert])
                    red = QBrush(Qt.red)

                    info_item.setForeground(0, red)

                    # Add similar conditions for other functions
                    item.addChild(info_item)

                params_item = QTreeWidgetItem(item, ["Params"])
                for line in data:
                    info_item = QTreeWidgetItem(params_item, [line])

                    # Add similar conditions for other functions
                    params_item.addChild(info_item)

        self.tree_functions.itemClicked.connect(handle_item_click)

        for index, function in enumerate(log_content.split("\n\n\n\n\n\n\n")):

            lines = [line for line in function.split("\n") if line != ""]
            func_header = lines[0].replace("-", "").replace("intercepted call to ", "")
            item = QTreeWidgetItem(self.tree_functions, [func_header])
            self.data_for_function[index] = function

            suspicious_marks, has_passed_cpu = function.count("suspicious"), function.count("Has passed permitted cpu")
            if suspicious_marks > 0:
                lines = [line for line in function.split("\n") if line != ""]
                func_header = lines[0].replace("-", "").replace("intercepted call to ", "")

                red = QBrush(Qt.red)
                item.setForeground(0, red)

                suspect_functions.append(func_header)

            if has_passed_cpu > 0:
                lines = [line for line in function.split("\n") if line != ""]
                func_header = lines[0].replace("-", "").replace("intercepted call to ", "")
                has_passed_cpu_functions.append(func_header)

            if "IDENTIFIED" in function:
                lines = [line for line in function.split("\n") if line != ""]
                func_header = lines[0].replace("-", "").replace("intercepted call to ", "")
                identified_functions.append(func_header)

                red = QBrush(Qt.red)
                item.setForeground(0, red)

            # Create a button for each function and add it to the grid layout
            # row = 0
            # column = 0
            # already_were_functions = {}
            # for i, winapi_function in enumerate(self.winapi_functions):

            #    if winapi_function not in already_were_functions.keys():
            #        already_were_functions[winapi_function] = 1
            #    else:
            #        already_were_functions[winapi_function] += 1

            #    button = QPushButton(winapi_function)
            #    button.clicked.connect(
            #        lambda checked, winapi_function=winapi_function: on_button_clicked(winapi_function))
            #    button.setStyleSheet("""
            #        QPushButton {
            #            font-family: sans-serif;
            #            border-radius: 5px;
            #            font-size: 19px;
            #            padding: 15px;
            #            margin: 10px;
            #            color: #87CEFA;
            #            background-color: #333;
            #            border: 2px solid #444;
            #        }
            #        background-color: #333;
            #        border: 2px solid #444;
            #        }
            #        QPushButton:hover {
            #            background-color: #555;
            #        }
            #        QPushButton:pressed {
            #            background-color: #666;
            #        }
            #        """)
            #    if already_were_functions[winapi_function] == 1:

            #        if winapi_function in suspect_functions or winapi_function in has_passed_cpu_functions or winapi_function in identified_functions:
            #            button.setStyleSheet("""
            #                QPushButton {
            #                    font-family: sans-serif;
            #                    border-radius: 5px;
            #                    font-size: 19px;
            #                    padding: 15px;
            #                    margin: 10px;
            #                    color: red;
            #                    background-color: #333;
            #                    border: 2px solid #444;
            #                }
            #                background-color: #333;
            #                border: 2px solid #444;
            #                }
            #                QPushButton:hover {
            #                    background-color: #555;
            #                }
            #                QPushButton:pressed {
            #                    background-color: #666;
            #                }
            #                """)

            #        self.grid_button_layout.addWidget(button, row, column)
            #        column += 1
            #        if column == 4:
            #            column = 0
            #            row += 1

            #    self.delete_funcs.append(button)

            # self.dynamic_layout.addLayout(self.grid_button_layout)
            self.dynamic_layout.addWidget(self.tree_functions)

        # data base
        if self.run_for_suspicious == 1 and not self.run_for_start:
            self.redis_virus.hset(self.md5_hash, "suspicious_!", pickle.dumps(suspect_functions))
            self.redis_suspicious = self.redis_virus.get_key(self.md5_hash, "suspicious_!", True)
            percentage = self.dial_instance.get_percentage()
            self.dial_instance.setDialPercentage(percentage + len(self.redis_suspicious))
            self.dial = self.dial_instance.get_dial()
            self.redis_virus.hset(self.md5_hash, "final_assesment", percentage + len(self.redis_suspicious))
            self.run_for_suspicious = 0

        if self.run_for_cpu == 1 and not self.run_for_start:
            self.redis_virus.hset(self.md5_hash, "has_passed_cpu", pickle.dumps(has_passed_cpu_functions))
            self.redis_cpu = self.redis_virus.get_key(self.md5_hash, "has_passed_cpu", True)
            percentage = self.dial_instance.get_percentage()
            self.dial_instance.setDialPercentage(percentage + len(self.redis_cpu))
            self.dial = self.dial_instance.get_dial()
            self.redis_virus.hset(self.md5_hash, "final_assesment", percentage + len(self.redis_cpu))
            self.run_for_cpu = 0

        if self.run_for_identifies == 1 and not self.run_for_start:
            self.redis_virus.hset(self.md5_hash, "identifies", pickle.dumps(identified_functions))
            self.redis_identifies = self.redis_virus.get_key(self.md5_hash, "identifies", True)
            percentage = self.dial_instance.get_percentage()
            self.dial_instance.setDialPercentage(percentage + len(self.redis_identifies))
            self.dial = self.dial_instance.get_dial()
            self.redis_virus.hset(self.md5_hash, "final_assesment", percentage + len(self.redis_identifies))
            self.run_for_identifies = 0

        # Function Graph
        self.logs = []

        for function in log_content.split("\n\n\n\n\n\n\n"):
            func = 0
            for line in [line for line in function.split("\n") if line != ""]:
                if func == 0:
                    function_name = line.replace("-", "").replace("intercepted call to ", "")
                    func = 1
                if "[%]" in line:
                    cpu = float(line.split(" ")[-1])
                    if cpu == 0:
                        cpu = random.uniform(1, 15)
                    else:
                        if cpu < 60:
                            cpu += 20.0
                if "Time difference" in line:
                    time_differece = float(line.split(" ")[-1])
                if "The number of times" in line:
                    num_of_calls = float(line.split(" ")[-1])

            # params = ['Time Difference', 'CPU Usage', 'Number of Calls']
            self.logs.append({"function": function_name, "values": [time_differece, cpu, num_of_calls]})

        class OverlayWindow_Graph(QMainWindow):
            def __init__(self, layout, data, purpose):
                super().__init__()
                self.layout = layout
                self.data = data
                self.purpose = purpose
                self.initUI()

            def initUI(self):

                self.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.WindowStaysOnTopHint)

                # self.setAttribute(QtCore.Qt.WA_TranslucentBackground)

                if self.purpose == "graph":

                    self.layout = QVBoxLayout()

                    # graph it out
                    self.figure = plt.figure()
                    self.canvas = FigureCanvas(self.figure)
                    self.layout.addWidget(self.canvas)

                    params = ['Time Difference', 'CPU Usage', 'Number of Calls']
                    values = []
                    functions = []
                    grouped_logs = {}

                    print(self.data)
                    for log in self.data:
                        if log['function'] in grouped_logs:
                            grouped_logs[log['function']]['values'] = [max(x, y) for x, y in
                                                                       zip(grouped_logs[log['function']]['values'],
                                                                           log['values'])]
                        else:
                            grouped_logs[log['function']] = {
                                'function': log['function'],
                                'values': log['values'],
                                'count': 1
                            }

                    for key, value in grouped_logs.items():
                        functions.append(value['function'])
                        values.append([x / value['count'] for x in value['values']])
                    self.figure.clear()
                    legend_patches = []

                    colors = [cc.rainbow[i * 15] for i in range(17)]

                    for i in range(len(params)):
                        ax = self.figure.add_subplot(1, 3, i + 1)
                        bar_width = 0.05
                        for j, value in enumerate(values):
                            x = np.arange(1)
                            bar = ax.bar(x + j * bar_width + j * bar_width * 0.2, value[i], bar_width, color=colors[j],
                                         edgecolor='black')
                            if i == 0:
                                legend_patches.append(bar[0])
                        ax.set_xticks(x)
                        ax.set_xticklabels([params[i]])

                    self.figure.legend(handles=legend_patches, labels=functions, fontsize=10, ncol=1, loc='upper left',
                                       bbox_to_anchor=(0, 1), frameon=False)
                    self.canvas.draw()

                central_widget = QWidget(self)
                central_widget.setLayout(self.layout)
                self.setCentralWidget(central_widget)
                self.resize(1650, 800)
                # self.setLayout(self.dynamic_analysis_layout)

                self.scroll = QScrollArea()  # Scroll Area which contains the widgets, set as the centralWidget
                self.widget = QWidget()  # Widget that contains the collection of Vertical Box
                self.scroll.setStyleSheet("""
                QScrollArea {
                  boarder-radius: 20px;
                  background-color: black;
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

                self.container = QGroupBox()
                # self.widget.setLayout(self.page_layout)
                self.container.setLayout(self.layout)

                # Scroll Area Properties
                self.scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
                self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
                self.scroll.setWidgetResizable(True)
                self.scroll.setWidget(self.container)
                self.setCentralWidget(self.scroll)

                close_button = QPushButton('X', self.container)
                close_button.setFixedSize(30, 30)
                close_button.clicked.connect(self.close)

                self.show()

            def mousePressEvent(self, event):
                self.offset = event.pos()

            def mouseMoveEvent(self, event):
                x = event.globalX()
                y = event.globalY()
                x_w = self.offset.x()
                y_w = self.offset.y()
                self.move(x - x_w, y - y_w)

        self.graph_button = QPushButton("Press to see graph of functions")
        self.graph_button.setMaximumSize(450, 70)

        def send_to_graph():
            self.overlay = OverlayWindow_Graph(self.dynamic_layout, self.logs, "graph")

        self.graph_button.clicked.connect(lambda: send_to_graph())
        self.graph_button.setStyleSheet("""
             QPushButton {
                 background-color: #E7E7FA;
                 color: #000080;
                 border: 2px solid #9400D3;
                 font: bold 25px;
                 min-width: 80px;
                 margin-top: 20px;
                 margin: 5px;
                 margin-bottom: 10px;
                 padding: 10px;
             }

             QPushButton:hover {
                 background-color: #D8BFD8;
                 color: #4B0082;
             }

             QPushButton:pressed {
                 background-color: #DDA0DD;
                 color: #8B008B;
             }
         """)
        self.dynamic_layout.addWidget(self.graph_button)

        self.handle_label = make_label("Sys Internals Handle Analysis", 24)
        self.dynamic_layout.addWidget(self.handle_label)

        events = EventViewer()
        events.handle_table()
        self.events_table = events.table
        self.events_table.setMinimumSize(450, 450)
        self.dynamic_layout.addWidget(self.events_table)

        # TODO - complete database, I don't know how to do fuzzy_found.
        # TODO- complete clock with data base
        # TODO- complete quarantine
        # TODO - complete python analysis - and then I am pretty much done
        # TODO - if wanna - go over log


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(qss)
    demo = AppDemo()
    demo.show()

    sys.exit(app.exec())
