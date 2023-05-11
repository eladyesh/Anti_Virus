import ctypes
import sys, os
import random
import threading
import socket
import wmi
import psutil
import pydivert
import pyuac
import win32api
import win32con
import win32file
from pydivert import WinDivert
from pyuac import main_requires_admin
from PyQt5.QtWidgets import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5 import QtCore, QtGui
from PyQt5.QtCore import Qt, QUrl, pyqtSlot, QRunnable, QThreadPool, QVariant, QAbstractTableModel, QRectF, QTimer, \
    QEventLoop, QSize, QMetaObject, QEvent, QDir
import PyQt5.QtGui
from PyQt5.QtCore import QObject, QThread, pyqtSignal
import shutil
from poc_start.unrelated.graphics.quarantine import Quarantine
from poc_start.unrelated.graphics.helpful_widgets import DialWatch, EventViewer, show_loading_menu, StatusBar, \
    MessageBox, show_message_warning_box, my_path_object, stop_timer, invoke_progress_bar_dir, invoke_progress_bar_ip, \
    worker_for_function, show_loading_menu_image, OverLayQuarantined
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
QToolTip {
    color: #87CEFA;
    background-color: #333;
    border: 2px solid #444;
    border-radius: 5px;
    font-family: sans-serif;
    font-size: 14px;
    padding: 5px;
    margin-top: 10px;
    margin-bottom: 10px;
}
"""

run_for_show_virtual_machine = 1
stop_threads_for_fuzzy = False
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
    "Microsoft_Visual_Cpp_80_DLL": "The Microsoft Visual C++ 80 DLL (also known as MSVCR80.dll) is a Dynamic Link "
                                   "Library file that contains a collection of pre-written code and data that can be "
                                   "used by multiple programs at the same time. ",
    "VC8_Microsoft_Corporation": "VC8 is a common abbreviation for Microsoft Visual C++ 2005, which is a set of "
                                 "tools and libraries used for developing C++ applications on the Windows platform. ",
    "SetFilePointer": "This function stores the file pointer in two LONG values",
    "GetKeyboardState": "Copies the status of the 256 virtual keys to the specified buffer.",
    "PyInstaller_Package": "A program that can be used to package Python programs into standalone executable files "
                           "for distribution. "
}


def run_as_admin(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not pyuac.isUserAdmin():
            print("Re-launching as admin!")
            pyuac.runAsAdmin()
        else:
            func(*args, **kwargs)  # Already an admin here.

    return wrapper


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


class worker_for_vm(QObject, threading.Thread):
    vm_changed = pyqtSignal()

    def __init__(self):
        super().__init__()

    def run(self):
        global run_for_show_virtual_machine
        # Monitor the file
        while not "vmware-vmx.exe" in [p.name() for p in psutil.process_iter()]:
            time.sleep(25)
        if wait_longer_for_vm:
            print("got to wait for long")
            time.sleep(40)
        else:
            time.sleep(15)

        # File found, emit signal
        self.vm_changed.emit()


class worker_for_upload_remove(QObject, threading.Thread):
    file_is_loaded = pyqtSignal()

    def __init__(self):
        super().__init__()

    def run(self):
        # Monitor the file
        while not os.path.exists("virus.exe"):
            time.sleep(1)

        self.file_is_loaded.emit()


class worker_for_files(QObject, threading.Thread):
    file_changed = pyqtSignal()

    def __init__(self):
        super().__init__()

    def run(self):
        # Monitor the file
        while not os.path.exists('LOG.txt'):
            time.sleep(1)

        # File found, emit signal
        self.file_changed.emit()


class worker_for_virus_dial(QObject, threading.Thread):
    dial_changed = pyqtSignal()

    def __init__(self, dial_instance):
        super().__init__()
        self.dial_instance = dial_instance

    def run(self):

        try:
            # Monitor the dial
            while not self.dial_instance.get_percentage() > 73:
                time.sleep(1)
        except RuntimeError:
            pass

        # File found, emit signal
        self.dial_changed.emit()


class worker_for_static_analysis(QObject, threading.Thread):
    static_is_ready = pyqtSignal()

    def run(self):

        try:
            # Monitor the dial
            while not worker_for_function.is_emitted:
                time.sleep(0.5)
        except RuntimeError:
            pass

        # File found, emit signal
        self.static_is_ready.emit()


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
    def __init__(self, status_bar, parent=None):
        super().__init__(parent)
        self.status_bar = status_bar

        # perform drag and drop
        self.setAcceptDrops(True)
        self.setGeometry(0, 0, 600, 500)
        self.move(300, 150)

        self.movie = QMovie("images/drag_and_drop.gif")
        self.gif_label = QLabel(self)
        self.gif_label.mousePressEvent = self.upload_files
        self.gif_label.setMovie(self.movie)
        self.movie.start()

        # create layout
        layout = QVBoxLayout(self)
        hlayout = QHBoxLayout()
        hlayout.addStretch()
        hlayout.addWidget(self.gif_label, alignment=Qt.AlignCenter)
        hlayout.addStretch()
        layout.addLayout(hlayout)
        layout.addStretch()

        button_clear_layout = QHBoxLayout()
        self.remove_button = QPushButton("Remove From System", self)
        self.remove_button.clicked.connect(self.remove_files_of_exe)
        self.remove_button.setCursor(Qt.PointingHandCursor)
        self.remove_button.setStyleSheet('''
            QPushButton {
                background-color: #E7E7FA;
                color: #000080;
                border: 2px solid #9400D3;
                font: bold 14px;
                margin: 5px;
                margin-bottom: 10px;
                padding: 6px;
                transition: all 0.5s cubic-bezier(0.25, 0.1, 0.25, 1.0);
                box-shadow: 0px 2px 2px rgba(0, 0, 0, 0.3);
            }

            QPushButton::indicator {
                width: 0;
                height: 0;
                padding: 0;
                margin: 0;
            }

            QPushButton#upload:checked {
                background-color: #FF6666;;
            }

            QPushButton#upload:active {
                transform: translateY(2px);
                box-shadow: 0px 0px 0px rgba(0, 0, 0, 0.3);
            }

            QPushButton#remove {
                background-color: #FF5252;
            }

             QPushButton:hover {
                 background-color: #D8BFD8;
                 color: #4B0082;
             }

             QPushButton:pressed {
                 background-color: #DDA0DD;
                 color: #8B008B;
             }
        ''')
        self.remove_button.setCheckable(True)
        self.remove_button.setObjectName('upload')
        self.remove_button.setChecked(True) if os.path.exists("virus.exe") else ""
        font = QFont()
        font.setBold(True)
        self.remove_button.setFont(font)
        self.remove_button.setDisabled(True)

        button_clear_layout.addWidget(self.remove_button, alignment=Qt.AlignBottom | Qt.AlignLeft)

        spacer = QSpacerItem(1200, 0, QSizePolicy.Expanding, QSizePolicy.Expanding)
        button_clear_layout.addSpacerItem(spacer)
        button_clear_layout.addStretch()  # add spacer item

        self.clear_icon = QLabel(self)
        self.clear_icon.setPixmap(QPixmap("images/clean.png"))
        self.clear_icon.setVisible(False)
        self.clear_icon.mousePressEvent = self.clearListWidget
        button_clear_layout.addWidget(self.clear_icon, alignment=Qt.AlignBottom | Qt.AlignRight)
        button_clear_layout.addStretch()  # add spacer item
        layout.addLayout(button_clear_layout)

    def remove_files_of_exe(self):

        show_message_warning_box("All the relevant analysis files will de deleted, and the application will exit.\n"
                                 "If you want the file to not be saved wait for system to reboot "
                                 "\n"
                                 "and remove it from that data base in the configurations tab")
        os.system("python delete_files.py")

        # result = subprocess.run(['python', 'quarantine.py'] + [self.path_for_file], capture_output=True, text=True) --> use this in real
        # Quit the application
        # The `QApplication.quit()` function terminates the application
        QApplication.quit()

    def upload_files(self, event):

        # Button is not checked, prompt user to select file and add it to list
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        file_dialog.setNameFilter("All Files (*)")
        file_dialog.setOption(QFileDialog.DontUseNativeDialog)
        file_dialog.setOption(QFileDialog.DontUseCustomDirectoryIcons)
        file_dialog.setOption(QFileDialog.ReadOnly)
        file_dialog.setOption(QFileDialog.HideNameFilterDetails)
        file_dialog.setOption(QFileDialog.DontResolveSymlinks)
        file_dialog.setViewMode(QFileDialog.Detail)
        file_dialog.setOption(QFileDialog.DontUseSheet)
        file_dialog.setOption(QFileDialog.DontUseNativeDialog)
        file_dialog.setOption(QFileDialog.ReadOnly)
        file_dialog.setOption(QFileDialog.DontUseCustomDirectoryIcons)
        file_dialog.setOption(QFileDialog.DontResolveSymlinks)
        file_dialog.setOption(QFileDialog.HideNameFilterDetails)
        if file_dialog.exec_() == QDialog.Accepted:
            selected_file = file_dialog.selectedFiles()[0]
            if selected_file:
                if self.count():
                    show_message_warning_box("There is already a file in the drag box")
                    self.remove_button.setChecked(False)
                else:
                    self.addItem(selected_file)
                    self.toggleClearIcon()
                    try:
                        self.gif_label.hide()
                    except RuntimeError:
                        pass
        else:
            show_message_warning_box("You must choose a real path")
            self.remove_button.setChecked(False)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.clear_icon.move(self.width() - self.clear_icon.width() - 10, self.height() - self.clear_icon.height() - 10)

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.setDropAction(Qt.CopyAction)
            event.accept()
        else:
            event.ignore()

    def clearListWidget(self, event=None):
        self.clear()
        self.clear_icon.setVisible(False)
        self.gif_label.show()

    def toggleClearIcon(self):
        if self.count() > 0:
            self.clear_icon.setVisible(True)
        else:
            self.clear_icon.setVisible(False)

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

            try:
                self.addItems(links)
                self.gif_label.hide()
                # self.gif_label.deleteLater()
            except RuntimeError:
                pass
        else:
            event.ignore()

        self.toggleClearIcon()


class AppDemo(QMainWindow):
    # define static variables
    keylogger_found = False
    suspected_keylogger = False
    suspected_python_file = False
    keylogger_suspect_imports = []
    keylogger_suspect_funcs = []
    keylogger_suspect_funcs_and_params = {}
    keylogger_suspect_patterns = []
    keylogger_suspect_params = []

    def __init__(self):
        super().__init__()

        self.flag = False
        self.setWindowTitle("AntiVirus")
        self.setWindowIcon(QIcon("images/virus.png"))

        self.activate_virus_total = True
        self.file_loaded_to_system = False
        self.vault_file = True

        self.save_in_data_base = True
        self.redis_virus = Redis()
        self.redis_virus.print_all()

        self.run_for_static_disable = 1
        self.run_for_hash_disable = 1
        self.run_for_dynamic_disable = 1
        self.run_for_dial_initiative = 0
        self.new_file_path_quarantined = ""
        self.path_for_file = ""

        # to save imports
        self.run_for_copy = 1
        self.copy_imports = {}

        if os.path.exists("virus.exe"):
            self.file_loaded_to_system = True
            self.run_for_dial_initiative = 1

        # status bar
        self.statusBar_instance = StatusBar()
        self.statusBar = self.statusBar_instance.get_instance()
        self.setStatusBar(self.statusBar)
        self.messages = []

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

        self.jump_to_top_action = QAction(QIcon("images/jump_to_top.png"), "Jump to top of the screen", self)
        self.jump_to_top_action.triggered.connect(lambda: self.scroll.verticalScrollBar().setValue(0))
        self.jump_to_top_action.setVisible(False)

        self.toolbar.addAction(self.main_menu_action)
        # self.toolbar.addAction(self.file_analysis_action)
        self.toolbar.addAction(self.directory_analysis)
        self.toolbar.addAction(self.ip_analysis_action)
        self.toolbar.addAction(self.about_action)
        self.toolbar.addAction(self.settings_action)

        spacer = QWidget(self)
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.toolbar.addWidget(spacer)

        self.toolbar.addAction(self.jump_to_top_action)

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
        self.run_for_python_win_api = 1

        self.main_menu_window()

    def updateActionVisibility(self, value):
        # Determine whether to show or hide the QAction based on the scroll position
        if value > 0:
            self.jump_to_top_action.setVisible(True)
        else:
            self.jump_to_top_action.setVisible(False)

    def update_dial_position(self, event=None):

        # Calculate the new position of the label widget based on the size of the window
        label_width = self.dial.sizeHint().width()
        window_width = self.width()
        x = window_width - label_width
        self.dial.move(x - 20, 20)

    def show_settings(self):

        self.clearLayout()
        self.dynamic_visited = False
        self.python_visited = False
        self.static_visited = False
        self.ip_visited = False
        self.hash_visited = False
        self.dir_visited = False

        self.settings_layout = QVBoxLayout()
        self.page_layout.addLayout(self.settings_layout)

        self.line_for_start = QLabel()
        self.line_for_start.setFrameStyle(QFrame.Box | QFrame.Plain)
        self.line_for_start.setLineWidth(2)
        self.line_for_start.setFixedHeight(50)
        self.line_for_start.setStyleSheet("border-color: purple; color: purple;")
        self.settings_layout.addWidget(self.line_for_start)

        self.vt_toggel = AnimatedToggle(
            checked_color="red",
            pulse_checked_color="red",
            pulse_unchecked_color="green"
        )

        self.vt_toggel.setChecked(False) if self.activate_virus_total else self.vt_toggel.setChecked(True)
        self.vt_toggel.setMaximumSize(100, 50)
        self.vt_message = QLabel("Do you want to turn off Virus Total search?\n(Red means off, unchecked means on)")
        self.vt_message.setFont(QFont("Zapfino", 16))
        self.vt_hbox = QHBoxLayout()
        self.vt_hbox.addWidget(self.vt_message)
        self.vt_hbox.addWidget(self.vt_toggel)
        self.settings_layout.addLayout(self.vt_hbox)

        # Create a vertical line between the toggles
        self.line_for_vt = QLabel()
        self.line_for_vt.setFrameStyle(QFrame.Box | QFrame.Plain)
        self.line_for_vt.setLineWidth(2)
        self.line_for_vt.setFixedHeight(self.vt_toggel.height())
        self.line_for_vt.setStyleSheet("border-color: purple; color: purple;")

        self.settings_layout.addWidget(self.line_for_vt)

        self.quarantine_toggle = AnimatedToggle(
            checked_color="red",
            pulse_checked_color="red",
            pulse_unchecked_color="green"
        )
        self.quarantine_toggle.setChecked(False) if self.vault_file else self.quarantine_toggle.setChecked(True)
        self.quarantine_toggle.setMaximumSize(100, 50)
        self.quarantine_message = QLabel(
            "Do you want to turn off vaulting of your file if found malicious?\n(Red means off, unchecked means on)")
        self.quarantine_message.setFont(QFont("Zapfino", 16))
        self.quarantine_hbox = QHBoxLayout()
        self.quarantine_hbox.addWidget(self.quarantine_message)
        self.quarantine_hbox.addWidget(self.quarantine_toggle)
        self.settings_layout.addLayout(self.quarantine_hbox)

        self.line_for_q = QLabel()
        self.line_for_q.setFrameStyle(QFrame.Box | QFrame.Plain)
        self.line_for_q.setLineWidth(2)
        self.line_for_q.setFixedHeight(self.vt_toggel.height())
        self.line_for_q.setStyleSheet("border-color: purple; color: purple;")

        self.settings_layout.addWidget(self.line_for_q)

        self.data_base_toggle = AnimatedToggle(
            checked_color="red",
            pulse_checked_color="red",
            pulse_unchecked_color="green"

        )
        self.data_base_toggle.setChecked(False) if self.save_in_data_base else self.data_base_toggle.setChecked(True)
        self.data_base_toggle.setMaximumSize(100, 50)
        self.data_base_message = QLabel(
            "Do you want to turn off saving file in data base?\n(Red means off, unchecked means on)")
        self.data_base_message.setFont(QFont("Zapfino", 16))
        self.data_base_hbox = QHBoxLayout()
        self.data_base_hbox.addWidget(self.data_base_message)
        self.data_base_hbox.addWidget(self.data_base_toggle)
        self.settings_layout.addLayout(self.data_base_hbox)

        self.line_for_data_base = QLabel()
        self.line_for_data_base.setFrameStyle(QFrame.Box | QFrame.Plain)
        self.line_for_data_base.setLineWidth(2)
        self.line_for_data_base.setFixedHeight(self.vt_toggel.height())
        self.line_for_data_base.setStyleSheet("border-color: purple; color: purple;")
        self.settings_layout.addWidget(self.line_for_data_base)

        self.apply_for_settings = QPushButton("Apply")
        self.apply_for_settings.setMaximumSize(250, 78)
        self.apply_for_settings.setMinimumSize(250, 78)
        self.apply_for_settings.setStyleSheet("""
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
         """)
        self.apply_for_settings.clicked.connect(self.func_for_settings)
        self.settings_layout.addWidget(self.apply_for_settings)
        self.settings_visited = True

    def create_file_dialog_for_quarantine(self):
        file_dialog = QFileDialog()
        file_dialog.setWindowTitle("Choose a File to De-Quarantine")
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        file_dialog.setNameFilter("All Files (*)")
        file_dialog.setOption(QFileDialog.DontUseNativeDialog)
        file_dialog.setOption(QFileDialog.DontUseCustomDirectoryIcons)
        file_dialog.setOption(QFileDialog.ReadOnly)
        file_dialog.setOption(QFileDialog.HideNameFilterDetails)
        file_dialog.setOption(QFileDialog.DontResolveSymlinks)
        file_dialog.setViewMode(QFileDialog.Detail)
        file_dialog.setOption(QFileDialog.DontUseSheet)
        file_dialog.setOption(QFileDialog.DontUseNativeDialog)
        file_dialog.setOption(QFileDialog.ReadOnly)
        file_dialog.setOption(QFileDialog.DontUseCustomDirectoryIcons)
        file_dialog.setOption(QFileDialog.DontResolveSymlinks)
        file_dialog.setOption(QFileDialog.HideNameFilterDetails)
        file_dialog.setFilter(QDir.AllEntries | QDir.Hidden)
        if file_dialog.exec_() == QDialog.Accepted:
            selected_file = file_dialog.selectedFiles()[0]
            if "Found_Virus" not in selected_file:
                return None
            return selected_file
        else:
            return None

    def func_for_settings(self):

        if self.vt_toggel.isChecked():
            print("activate virus total is checked")
            self.activate_virus_total = False
            self.messages.append("You have turned Virus Total interfacing off")
        else:
            self.activate_virus_total = True
            self.messages.append("You have turned Virus Total interfacing back on")
        if self.quarantine_toggle.isChecked():

            # turning the vaulting off --> release the file from vault
            self.vault_file = False
            ## if os.path.exists(self.new_file_path_quarantined):
            ## Quarantine.restore_file("Found_Virus/virus.exe", "Found_Virus", "1234")
            # file = self.create_file_dialog_for_quarantine()
            # if file is not None:
            #     Quarantine.restore_quarantined_to_original(file, os.path.dirname(os.path.dirname(file))
            #                                                + r"\restored_file.exe", "1234")
            overlay_quarantined.add_data()
            overlay_quarantined.show()
            loop = QEventLoop()
            overlay_quarantined.closed.connect(loop.quit)
            loop.exec_()
            ##     # Quarantine.restore_quarantined_to_original(self.new_file_path_quarantined, self.path_for_file, "1234")
            if overlay_quarantined.name_to_quarantine is not None:
                self.messages.append(
                    f"You have turned the vault option off. Your file {overlay_quarantined.name_to_quarantine} is now "
                    f"restored")
            else:
                self.messages.append("You have turned the vault option off")
            overlay_quarantined.name_to_quarantine = None
        else:
            # leaving the vaulting
            self.vault_file = True
            self.messages.append("You have turned the vault option back on")
        if self.data_base_toggle.isChecked():
            if os.path.exists("virus.exe"):
                self.redis_virus.print_all()
                if self.redis_virus.exists(md5("virus.exe")):
                    self.redis_virus.delete(md5("virus.exe"))
                    self.save_in_data_base = False
                    self.redis_virus.print_all()
                    self.messages.append("Your file will now not be saved in data base")
                    self.dial_instance.setDialPercentage(0)
            else:
                show_message_warning_box("You didn't upload your file onto the system")

        self.main_menu_window()
        return

    def run_func_in_thread(self, func_to_run):

        self.thread = QThread()
        self.thread.run = func_to_run
        return self.thread

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
            self.v_box_for_imports.deleteLater()
            self.v_box_for_packers.deleteLater()
            self.h_box_for_packers_imports.deleteLater()
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

            if self.activate_virus_total:
                self.basic_info_label.deleteLater()
                self.basic_info.deleteLater()
                self.we_are_sorry_label.deleteLater()
            else:
                self.virus_total_shut_down_label.deleteLater()

            self.fuzzy_hash_label.deleteLater()
            self.fuzzy_hash_button.deleteLater()
            if self.delete_widgets is not None:
                try:
                    for widget in self.delete_widgets:
                        widget.deleteLater()
                except RuntimeError:
                    pass
            try:
                if self.fuzzy_spin is not None:
                    self.fuzzy_spin.deleteLater()
            except RuntimeError:
                pass

            if self.thread1 is not None and self.thread2 is not None and self.thread3 is not None and self.thread4 is not None:
                stop_threads_for_fuzzy = True
                self.thread1.terminate()
                self.thread1 = None

                self.thread2.terminate()
                self.thread2 = None

                self.thread3.terminate()
                self.thread3 = None

                self.thread4.terminate()
                self.thread4 = None

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
                self.searchButton_for_dir.deleteLater()
                self.searchBar_for_dir.deleteLater()
                self.searchLayout_for_dir.deleteLater()
                self.v_box_for_search_dir.deleteLater()
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
                self.searchButton_for_ip.deleteLater()
                self.searchBar_for_ip.deleteLater()
                self.searchLayout_for_ip.deleteLater()
                self.v_box_for_search_ip.deleteLater()
                self.movie_label_ip.deleteLater()
                self.ip_thread.terminate()

            self.ip_layout.deleteLater()

        if self.settings_visited:
            self.vt_toggel.deleteLater()
            self.vt_message.deleteLater()
            self.vt_hbox.deleteLater()
            self.quarantine_toggle.deleteLater()
            self.quarantine_message.deleteLater()
            self.quarantine_hbox.deleteLater()
            self.data_base_message.deleteLater()
            self.data_base_hbox.deleteLater()
            self.data_base_toggle.deleteLater()
            self.apply_for_settings.deleteLater()
            self.line_for_start.deleteLater()
            self.line_for_vt.deleteLater()
            self.line_for_q.deleteLater()
            self.line_for_data_base.deleteLater()
            self.settings_layout.deleteLater()

        if self.python_visited:
            self.python_label.deleteLater()
            if AppDemo.keylogger_found:  # AppDemo.keylogger_found
                self.keylogger_v_box_imports.deleteLater()
                self.keylogger_v_box_funcs.deleteLater()
                self.keylogger_v_box_funcs_params.deleteLater()
                self.first_line_of_lists.deleteLater()
                self.keylogger_v_box_params.deleteLater()
                self.keylogger_v_box_patterns.deleteLater()
                self.second_line_of_lists.deleteLater()
            else:
                self.tree_py.deleteLater()
            self.python_layout.deleteLater()

    def show_ip_analysis(self):

        self.clearLayout()
        self.dir_visited = False
        self.static_visited = False
        self.hash_visited = False
        self.dynamic_visited = False
        self.python_visited = False
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
        self.python_visited = False
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
        self.resize(1200, 720)

        self.listbox_view = ListBoxWidget(self.statusBar_instance, self)
        self.listbox_view.setMinimumSize(300, 247)
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
        self.load_for_static.clicked.connect(self.load_for_static_analysis)

        self.load_for_hash = QPushButton('Load for Hash Analysis', self)
        self.load_for_hash.clicked.connect(self.load_for_hash_analysis)

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
        spacer = QSpacerItem(300, 20, QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.h_box_for_l1_and_dial.addSpacerItem(spacer)
        self.h_box_for_l1_and_dial.addWidget(self.l1)
        spacer = QSpacerItem(200, 20, QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.h_box_for_l1_and_dial.addSpacerItem(spacer)
        self.h_box_for_l1_and_dial.setAlignment(Qt.AlignCenter)
        # self.h_box_for_l1_and_dial.addSpacerItem(QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Minimum))

        self.dial_instance = DialWatch()
        self.dial = self.dial_instance.get_dial()
        self.h_box_for_l1_and_dial.addWidget(self.dial, alignment=Qt.AlignRight)

        # setting after moving to home screen
        if self.save_in_data_base:
            if os.path.exists("virus.exe"):
                if self.redis_virus.exists(str(md5("virus.exe"))):
                    self.dial_instance.setDialPercentage(
                        int(self.redis_virus.get_key(str(md5("virus.exe")), "final_assesment", False)))
                    self.dial = str(md5("virus.exe"))

                    if self.run_for_dial_initiative == 1:
                        self.run_for_start = True
                        self.run_for_dial_initiative = 0

        self.l1.setStyleSheet("QLabel { font: bold; margin-bottom: 0px; padding: 10px;}")

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

        if self.run_for_dynamic_disable == 1:
            self.dynamic_button.setDisabled(True)

        self.static_button = QPushButton("Static Analysis")
        self.static_button.setStyleSheet(
            "QPushButton {background-color: #E6E6FA; color: #000080; border: 2px solid #9400D3; "
            "font: bold 25px; min-width: 80px; margin: 5px; margin-bottom: 10px;} "
            "QPushButton:hover {background-color: #D8BFD8; color: #4B0082;} QPushButton:pressed {"
            "background-color: #DDA0DD; color: #8B008B;}")
        self.static_button.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.static_button.setFlat(True)

        if self.run_for_static_disable == 1:
            self.static_button.setDisabled(True)

        self.hash_button = QPushButton("Hash Analysis")
        self.hash_button.setStyleSheet(
            "QPushButton {background-color: #E6E6FA; color: #000080; border: 2px solid #9400D3; "
            "font: bold 25px; min-width: 80px; margin: 2px; margin-left: 10px; margin-bottom: 10px; "
            "border-top-right-radius: 20px;} "
            "QPushButton:hover {background-color: #D8BFD8; color: #4B0082;} QPushButton:pressed {"
            "background-color: #DDA0DD; color: #8B008B;}")
        self.hash_button.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.hash_button.setFlat(True)

        if self.run_for_hash_disable == 1:
            self.hash_button.setDisabled(True)

        # btn_layout.addItem(Qt.SpacerItem(0, 0,QSizePolicy.Expanding, Qt.QSizePolicy.Minimum))
        # self.btn_layout.addStretch(1)
        self.btn_layout.addWidget(self.dynamic_button,
                                  Qt.AlignCenter)
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
        self.python_visited = False
        self.static_visited = False
        self.hash_visited = False
        self.dir_visited = False
        self.ip_visited = False
        self.settings_visited = False

        self.scroll = QScrollArea()  # Scroll Area which contains the widgets, set as the centralWidget

        # connect the scrollbar to the slot
        self.scroll.verticalScrollBar().valueChanged.connect(lambda value: self.updateActionVisibility(value))

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
        self.static_button.clicked.connect(lambda: [self.activate_static_analysis()])
        self.hash_button.clicked.connect(lambda: [self.activate_hash_analysis()])
        self.dynamic_button.clicked.connect(lambda: [self.dynamic_analysis()])

        # initiate threads
        # Create a worker thread to monitor the file
        self.worker = worker_for_files()
        self.worker.file_changed.connect(self.on_file_changed)
        self.worker.start()

        # for quarantine
        self.worker_for_dial = worker_for_virus_dial(self.dial_instance)
        self.worker_for_dial.dial_changed.connect(self.on_probability_changed)
        self.worker_for_dial.start()

        # for vm start
        self.worker_for_vm = worker_for_vm()
        self.worker_for_vm.vm_changed.connect(lambda: self.statusBar_instance.show_message("VM is now running, you "
                                                                                           "can send your file. When "
                                                                                           "the log is ready, "
                                                                                           "you wil get a "
                                                                                           "notification in the "
                                                                                           "status bar"))
        self.worker_for_vm.start()

        def activate_remove_button():
            try:
                if self.listbox_view.remove_button:
                    self.listbox_view.remove_button.setDisabled(False)
                    self.listbox_view.remove_button.setChecked(True)
            except RuntimeError:
                pass

        # for the upload / remove button
        self.worker_for_upload_remove = worker_for_upload_remove()
        self.worker_for_upload_remove.file_is_loaded.connect(activate_remove_button)
        # lambda: [self.listbox_view.remove_button.setDisabled(False),
        #          self.listbox_view.remove_button.setChecked(True)])
        self.worker_for_upload_remove.start()

        # for status bar
        if self.messages != []:
            self.statusBar_instance.show_few(self.messages)
            self.messages = []

    def on_file_changed(self):
        if self.run_for_dynamic_disable == 1:
            self.statusBar_instance.show_message('LOG is ready, check Dynamic Analysis')
            self.dynamic_button.setDisabled(False)
            self.run_for_dynamic_disable = 0

    def on_probability_changed(self):

        # Create a QTimer object
        timer = QTimer()

        # Start the timer and set its timeout to 10 seconds
        timer.start(10000)

        # Enter the local event loop until the timer has finished
        loop = QEventLoop()
        timer.timeout.connect(loop.quit)
        loop.exec_()

        if self.path_for_file == "":
            return

        # Check if the boolean variable `self.vault_file` is truth
        if self.vault_file and self.dial_instance.get_percentage() > 73 and not os.path.exists(
                os.path.dirname(self.path_for_file) + r"\Found_Virus"):
            # Display a warning message box to the user

            show_message_warning_box("Your file has now been quarantined for it is found to be a virus.\n"
                                     "You will not be able to run the file.\n\n"
                                     "If you wish to now restore file, you may go the configuration window\n"
                                     "and turn off the option\n\n"
                                     "Once you leave this message, the file will be vaulted\n"
                                     "and you will not be able to run it from the path you have submitted to this "
                                     "system")

            # Run the Python script `quarantine.py`
            # The `os.system()` function executes a command in a subshell
            # In this case, the command is to run the `quarantine.py` script

            # os.system("python quarantine.py")
            # result = subprocess.run(['python', 'quarantine.py'] + [self.path_for_file], capture_output=True, text=True) --> use this in real

            if not os.path.exists(os.path.dirname(self.path_for_file) + r"\Found_Virus"):
                # new_file_path = Quarantine.quarantine_file("virus.exe", "Found_Virus", "1234")
                self.new_file_path_quarantined = Quarantine.quarantine_file(self.path_for_file, os.path.dirname(
                    self.path_for_file) + r"\Found_Virus", "1234")
                Quarantine.hide(os.path.dirname(self.new_file_path_quarantined))
                self.messages.append("Your have has now been quarantined and locked in it's original dir")
                self.main_menu_window()

                # Define constants for file attributes
                # FILE_ATTRIBUTE_NORMAL = 0x80
                # FILE_ATTRIBUTE_HIDDEN = 0x2
                # FILE_ATTRIBUTE_READONLY = 0x1
                # FILE_ATTRIBUTE_EXECUTABLE = 0x40
                #
                # # Set file attributes to non-executable
                # filename = "virus.exe"
                # attrs = FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY
                # attrs = attrs & ~FILE_ATTRIBUTE_EXECUTABLE  # remove executable attribute
                # ctypes.windll.kernel32.SetFileAttributesW(filename, attrs)

                return

            # Quit the application
            # The `QApplication.quit()` function terminates the application
            # QApplication.exit()

    def load_for_static_analysis(self):
        self.run_for_static_disable = 0
        if self.file_loaded_to_system:
            print("got to self.file")
            self.static_button.setDisabled(False)
            self.statusBar_instance.show_message("Static Analysis is ready")
            return
        else:
            item = QListWidgetItem(self.listbox_view.item(0))
            self.path_for_file = item.text()

            # show warning message box for no file
            if self.path_for_file == "" and not os.path.exists("virus.exe"):
                show_message_warning_box("You have to enter a real path")
                return

            bytes = b""
            try:
                with open(self.path_for_file, "rb") as f:
                    bytes += f.read()
                shutil.move(str(self.path_for_file), PATH_TO_MOVE + "\\virus.exe")
                with open(self.path_for_file, "wb") as f:
                    f.write(bytes)
            except Exception as e:
                print(e)
            self.file_loaded_to_system = True
            self.static_button.setDisabled(False)
            self.statusBar_instance.show_message("Static Analysis is ready")

            if self.save_in_data_base:
                if os.path.exists("virus.exe"):
                    if self.redis_virus.exists(str(md5("virus.exe"))):
                        self.dial_instance.setDialPercentage(
                            int(self.redis_virus.get_key(str(md5("virus.exe")), "final_assesment", False)))
                        self.dial = str(md5("virus.exe"))
                        self.run_for_start = True
                        print(self.run_for_start)

            if os.path.getsize("virus.exe") > 6000 * 1024:
                AppDemo.suspected_python_file = True

    def load_for_hash_analysis(self):
        self.run_for_hash_disable = 0
        if self.file_loaded_to_system:
            self.hash_button.setDisabled(False)
            self.statusBar_instance.show_message("Hash Analysis is ready")
            return
        else:
            item = QListWidgetItem(self.listbox_view.item(0))
            path = item.text()

            # show warning message box for no file
            if path == "" and not os.path.exists("virus.exe"):
                show_message_warning_box("You have to enter a real path")
                return

            bytes = b""
            try:
                with open(path, "rb") as f:
                    bytes += f.read()
                shutil.move(str(path), PATH_TO_MOVE + "\\virus.exe")
                with open(path, "wb") as f:
                    f.write(bytes)
            except Exception as e:
                print(e)
            self.file_loaded_to_system = True
            self.hash_button.setDisabled(False)
            self.statusBar_instance.show_message("Hash Analysis is ready")

            if self.save_in_data_base:
                if os.path.exists("virus.exe"):
                    if self.redis_virus.exists(str(md5("virus.exe"))):
                        self.dial_instance.setDialPercentage(
                            int(self.redis_virus.get_key(str(md5("virus.exe")), "final_assesment", False)))
                        self.dial = str(md5("virus.exe"))
                        self.run_for_start = True

    def python_analysis(self):

        self.clearLayout()
        self.dynamic_visited = False
        self.static_visited = False
        self.ip_visited = False
        self.hash_visited = False
        self.dir_visited = False
        self.settings_visited = False
        self.python_visited = True

        self.python_layout = QVBoxLayout()
        self.page_layout.addLayout(self.python_layout)
        self.python_label = make_label("Python Static Analysis", 24)
        self.python_label.setText("Python Static Analysis <img src='images/info-button.png' width='20' height='20'>")
        self.python_label.setToolTip("Full Static Code Analysis of Python Executables files:\n"
                                     "WinApi Executables\n"
                                     "Keyloggers")
        self.python_layout.addWidget(self.python_label)

        # self.pv = PythonVirus("virus.exe")
        # self.pv.log_for_winapi(self.pv.find_ctypes_calls())
        # self.keylogger_check = True
        # if len(AppDemo.keylogger_suspect_imports) == 0 and len(AppDemo.keylogger_suspect_funcs) == 0 \
        #     and len(AppDemo.keylogger_suspect_funcs_and_params) == 0 \
        #         and len(AppDemo.keylogger_suspect_patterns) == 0 \
        #         and len(AppDemo.keylogger_suspect_params) == 0:
        #             self.keylogger_check = False

        if AppDemo.keylogger_found:  # AppDemo.keylogger_found

            keylogger_style_sheet = """
            QListWidget {
                background-color: #333;
                border: 1px solid #ccc;
                border-radius: 5px;
                outline: none;
                margin: 7px;
                font-size: 20px;
                margin: 5px;
            }
            QListWidget::item {
                border: none;
                padding: 10px;
                font: 18px;
                font-weight: 500;
                color: red;
            }
            QListWidget::item[role=highlight] {
                color: red;
            }

            QListWidget::item:hover {
                background-color: #555;
            }
            """

            self.keylogger_imports = QListWidget()
            for imp in AppDemo.keylogger_suspect_imports:
                item = QListWidgetItem(imp)
                font = item.font()
                font.setPointSize(12)
                item.setFont(font)
                self.keylogger_imports.addItem(item)

            self.keylogger_imports.setStyleSheet(keylogger_style_sheet)
            # self.keylogger_imports.setMaximumSize(275, 250)
            self.keylogger_imports.setMinimumSize(275, 250)
            self.keylogger_imports.setVerticalScrollBar(self.create_scroll_bar())

            self.keylogger_funcs = QListWidget()
            for func in AppDemo.keylogger_suspect_funcs:
                item = QListWidgetItem(func)
                font = item.font()
                font.setPointSize(12)
                item.setFont(font)
                self.keylogger_funcs.addItem(item)

            self.keylogger_funcs.setStyleSheet(keylogger_style_sheet)
            # self.keylogger_funcs.setMaximumSize(275, 250)
            self.keylogger_funcs.setMinimumSize(275, 250)
            self.keylogger_funcs.setVerticalScrollBar(self.create_scroll_bar())

            self.keylogger_funcs_params = QListWidget()
            for func, param in AppDemo.keylogger_suspect_funcs_and_params.items():
                args = ', '.join(map(repr, AppDemo.keylogger_suspect_funcs_and_params[func]))
                function_call = f"{func}({args})"
                item = QListWidgetItem(function_call)
                font = item.font()
                font.setPointSize(12)
                item.setFont(font)
                self.keylogger_funcs_params.addItem(item)

            self.keylogger_funcs_params.setStyleSheet(keylogger_style_sheet)
            # self.keylogger_funcs_params.setMaximumSize(315, 250)
            self.keylogger_funcs_params.setMinimumSize(275, 250)
            self.keylogger_funcs_params.setVerticalScrollBar(self.create_scroll_bar())

            self.keylogger_patterns = QListWidget()
            for pattern in AppDemo.keylogger_suspect_patterns:
                item = QListWidgetItem(pattern)
                font = item.font()
                font.setPointSize(12)
                item.setFont(font)
                self.keylogger_patterns.addItem(item)

            self.keylogger_patterns.setStyleSheet(keylogger_style_sheet)
            # self.keylogger_patterns.setMaximumSize(275, 250)
            self.keylogger_patterns.setMinimumSize(275, 250)
            self.keylogger_patterns.setVerticalScrollBar(self.create_scroll_bar())

            self.keylogger_params = QListWidget()
            for param in AppDemo.keylogger_suspect_params:
                item = QListWidgetItem(param)
                font = item.font()
                font.setPointSize(12)
                item.setFont(font)
                self.keylogger_patterns.addItem(item)

            self.keylogger_params.setStyleSheet(keylogger_style_sheet)
            # self.keylogger_params.setMaximumSize(275, 250)
            self.keylogger_params.setMinimumSize(275, 250)
            self.keylogger_params.setVerticalScrollBar(self.create_scroll_bar())

            self.first_line_of_lists = QHBoxLayout()
            self.keylogger_v_box_imports = QVBoxLayout()
            self.keylogger_imports_label = make_label("Keylogger Imports", 19)
            self.keylogger_v_box_imports.addWidget(self.keylogger_imports_label)
            self.keylogger_v_box_imports.addWidget(self.keylogger_imports)
            self.first_line_of_lists.addLayout(self.keylogger_v_box_imports)

            self.keylogger_v_box_funcs = QVBoxLayout()
            self.keylogger_funcs_label = make_label("Keylogger Funcs", 19)
            self.keylogger_v_box_funcs.addWidget(self.keylogger_funcs_label)
            self.keylogger_v_box_funcs.addWidget(self.keylogger_funcs)
            self.first_line_of_lists.addLayout(self.keylogger_v_box_funcs)

            self.keylogger_v_box_funcs_params = QVBoxLayout()
            self.keylogger_funcs_params_label = make_label("Keylogger Funcs-Params", 19)
            self.keylogger_v_box_funcs_params.addWidget(self.keylogger_funcs_params_label)
            self.keylogger_v_box_funcs_params.addWidget(self.keylogger_funcs_params)
            self.first_line_of_lists.addLayout(self.keylogger_v_box_funcs_params)
            self.python_layout.addLayout(self.first_line_of_lists)

            self.second_line_of_lists = QHBoxLayout()
            self.keylogger_v_box_patterns = QVBoxLayout()
            self.keylogger_patterns_label = make_label("Keylogger Patterns", 19)
            self.keylogger_v_box_patterns.addWidget(self.keylogger_patterns_label)
            self.keylogger_v_box_patterns.addWidget(self.keylogger_patterns)
            self.second_line_of_lists.addLayout(self.keylogger_v_box_patterns)

            self.keylogger_v_box_params = QVBoxLayout()
            self.keylogger_params_label = make_label("Keylogger Params", 19)
            self.keylogger_v_box_params.addWidget(self.keylogger_params_label)
            self.keylogger_v_box_params.addWidget(self.keylogger_params)
            self.second_line_of_lists.addLayout(self.keylogger_v_box_params)
            self.python_layout.addLayout(self.second_line_of_lists)
            percentage = self.dial_instance.get_percentage()
            # AppDemo.keylogger_suspect_imports = self.keylogger_suspect[0]
            # AppDemo.keylogger_suspect_funcs = self.keylogger_suspect[1]
            # AppDemo.keylogger_suspect_funcs_and_params = self.keylogger_suspect[2]
            # AppDemo.keylogger_suspect_patterns = self.keylogger_suspect[3]
            # AppDemo.keylogger_suspect_params = self.keylogger_suspect[4]
            self.dial_instance.setDialPercentage(percentage + int(len(AppDemo.keylogger_suspect_imports)) * 3 +
                                                 int(len(AppDemo.keylogger_suspect_funcs)) * 3 +
                                                 int(len(AppDemo.keylogger_suspect_funcs_and_params)) * 2 +
                                                 int(len(AppDemo.keylogger_suspect_patterns)) * 2 +
                                                 int(len(AppDemo.keylogger_suspect_params)) * 2)

            self.redis_virus.hset(self.md5_hash, "final_assesment", percentage +
                                  int(len(AppDemo.keylogger_suspect_imports)) * 3 +
                                  int(len(AppDemo.keylogger_suspect_funcs)) * 3 +
                                  int(len(AppDemo.keylogger_suspect_funcs_and_params)) * 2 +
                                  int(len(AppDemo.keylogger_suspect_patterns)) * 2 +
                                  int(len(AppDemo.keylogger_suspect_params)) * 2)

            self.dial = self.dial_instance.get_dial()

        else:
            with open("log_python.txt", "r") as f:
                virus_python_winapi_data_base = 0
                python_data = f.read()
                python_data = python_data.split("\n\n")
                print(python_data)
                self.tree_py = QTreeWidget()
                self.tree_py.setMinimumSize(500, 500)
                self.tree_py.setStyleSheet("""
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
                self.tree_py.setHeaderLabel("Logged Functions")
                for func in python_data:
                    # function name
                    lines = func.split("\n")
                    for i, line in enumerate(lines):
                        if line.startswith("Function name: "):
                            function_name = line.split(": ")[1]
                            item = QTreeWidgetItem(self.tree_py, [function_name])
                            del lines[i]
                            break
                    lines = "\n".join(lines)
                    for line in lines.split("\n"):
                        if "=" in line or "Trying" in line or "" or "Found Injection to process" in line \
                                or "PID:" in line or "Parent PID:" in line or "The data being injected:" in line:
                            continue
                        child_item = QTreeWidgetItem([line])
                        item.addChild(child_item)
                for func in python_data:
                    if "==============REGISTRY CHANGE==============" in func:
                        for i, line in enumerate(func.split("\n")):
                            # first line
                            if i == 0:
                                item = QTreeWidgetItem(self.tree_py, ["REGISTRY CHANGE"])
                                item.setForeground(0, QBrush(QColor("red")))
                                virus_python_winapi_data_base += 35
                                continue
                            # last line
                            if "REGISTRY CHANGE" in line:
                                continue
                            child_item = QTreeWidgetItem([line])
                            child_item.setForeground(0, QBrush(QColor("red")))
                            item.addChild(child_item)
                    if "==============INJECTION==============" in func:
                        for i, line in enumerate(func.split("\n")):
                            # first line
                            if i == 0:
                                item = QTreeWidgetItem(self.tree_py, ["INJECTION"])
                                item.setForeground(0, QBrush(QColor("red")))
                                virus_python_winapi_data_base += 35
                                continue
                            # last line
                            if "INJECTION" in line:
                                continue
                            child_item = QTreeWidgetItem([line])
                            child_item.setForeground(0, QBrush(QColor("red")))
                            item.addChild(child_item)
                    if "==============PORT SCANNING==============" in func:
                        for i, line in enumerate(func.split("\n")):
                            # first line
                            if i == 0:
                                item = QTreeWidgetItem(self.tree_py, ["PORT SCANNING"])
                                item.setForeground(0, QBrush(QColor("darkorange")))
                                virus_python_winapi_data_base += 10
                                continue
                            # last line
                            if "PORT SCANNING" in line:
                                continue
                            child_item = QTreeWidgetItem([line])
                            child_item.setForeground(0, QBrush(QColor("darkorange")))
                            item.addChild(child_item)

            self.python_layout.addWidget(self.tree_py)

            if self.run_for_python_win_api:
                percentage = self.dial_instance.get_percentage()
                self.dial_instance.setDialPercentage(percentage + virus_python_winapi_data_base)
                self.redis_virus.hset(self.md5_hash, "final_assesment", percentage + virus_python_winapi_data_base)

                self.dial = self.dial_instance.get_dial()
                self.run_for_python_win_api = 0
        self.statusBar_instance.show_message("Your python analysis is ready")

    def getSelectedItem(self):
        item = QListWidgetItem(self.listbox_view.item(0))

        if not self.file_loaded_to_system:
            self.path_for_file = item.text()

        # show warning message box for no file
        if self.path_for_file == "" and not os.path.exists("virus.exe"):
            show_message_warning_box("You have to enter a real path")
            return

        if not self.file_loaded_to_system:
            bytes = b""
            try:
                with open(self.path_for_file, "rb") as f:
                    bytes += f.read()
                shutil.move(str(self.path_for_file), PATH_TO_MOVE + "\\virus.exe")
                with open(self.path_for_file, "wb") as f:
                    f.write(bytes)
            except Exception as e:
                print(e)
            self.file_loaded_to_system = True
            print(self.file_loaded_to_system)
            print("path is (in not loaded to the system ", self.path_for_file)

        # elif self.path_for_file != os.path.abspath("virus.exe"):
        #     self.path_for_file = os.path.abspath("virus.exe")
        #     print("path is (already loaded to system", self.path_for_file)

        # self.md5_hash = str(md5(r"E:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\graphics"
        #                         r"\virus.exe")) --> lab

        self.md5_hash = str(md5(os.getcwd() + r"\virus.exe"))
        # print(self.md5_hash, "Taken from ", os.path.abspath("virus.exe"))

        if self.save_in_data_base:
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

        if os.path.exists("log_python.txt") or len(AppDemo.keylogger_suspect_imports) > 2:
            self.python_analysis()
            return

        if Packers.programming_language(self.path_for_file) == "py":  # a python file
            # self.py_thread = QThread()
            # self.py_thread.run = self.python_analysis
            # self.py_thread.start()
            # self.show_loading_menu()

            class VirusThread(QThread):
                overlay = show_loading_menu("Loading your data...\nIt will take maximum of 2 minutes.\nWhen it is "
                                            "ready, "
                                            "it will be shown in the "
                                            "status bar")
                overlay.show()
                finished_signal = pyqtSignal()

                def run(self):
                    self.pv = PythonVirus("virus.exe")
                    self.pv.log_for_winapi(self.pv.find_ctypes_calls())

                    self.keylogger_suspect = self.pv.check_for_keylogger()
                    AppDemo.keylogger_suspect_imports = self.keylogger_suspect[0]
                    AppDemo.keylogger_suspect_funcs = self.keylogger_suspect[1]
                    AppDemo.keylogger_suspect_funcs_and_params = self.keylogger_suspect[2]
                    AppDemo.keylogger_suspect_patterns = self.keylogger_suspect[3]
                    AppDemo.keylogger_suspect_params = self.keylogger_suspect[4]
                    AppDemo.keylogger_found = False

                    if len(AppDemo.keylogger_suspect_imports) > 2 and len(AppDemo.keylogger_suspect_funcs) > 2 and len(
                            AppDemo.keylogger_suspect_funcs_and_params.keys()) > 1 and len(
                        AppDemo.keylogger_suspect_patterns) > 2:
                        AppDemo.keylogger_found = True

                    # signal the main thread that the task is finished
                    self.finished_signal.emit()

            # create an instance of VirusThread and start it

            virus_thread = VirusThread()
            virus_thread.start()

            # create a QEventLoop to wait until the task is finished
            loop = QEventLoop()
            virus_thread.finished_signal.connect(loop.quit)
            loop.exec_()

            VirusThread.overlay.close()
            self.python_analysis()
            return

        if Packers.programming_language(
                self.path_for_file) is not True:  # either not exe, or not written in the languages
            show_message_warning_box("Your file is not in the current format.\n"
                                     "The exe files that can be uploaded are only in:\n"
                                     "Python, C++, C, C#\n"
                                     "Please be aware and try again")
            os.remove("virus.exe")
            self.file_loaded_to_system = False
            self.listbox_view.clearListWidget()
            self.listbox_view.remove_button.setChecked(False)
            return

        while not os.path.exists(r"E:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\graphics"
                                 r"\virus.exe"):
            pass

        if os.path.exists("LOG.txt"):
            show_message_warning_box("The LOG already exists")
            self.listbox_view.clearListWidget()
            self.listbox_view.remove_button.setChecked(False)
            return

        if "vmware-vmx.exe" not in [p.name() for p in psutil.process_iter()]:
            show_message_warning_box("The virtual machine is not on")
            return

        if item.text() == "":
            show_message_warning_box("You have to enter a real path")
            return

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

        if "vmware-vmx.exe" in [p.name() for p in psutil.process_iter()]:
            return

        current_path = os.getcwd()
        os.chdir(r"C:\Program Files (x86)\VMware\VMware Workstation")
        os.system(r'vmrun -T ws start "C:\Users\u101040.DESHALIT\Documents\Virtual Machines\Windows 10 and later '
                  r'x64\Windows 10 and later x64.vmx"')
        os.chdir(current_path)

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

    def resizeEvent(self, event):
        try:
            # Set the resize mode of each column to Stretch --> virus pe table
            header = self.virus_table.horizontalHeader()
            header.setSectionResizeMode(QHeaderView.Stretch)
        except (AttributeError, RuntimeError):
            pass

        try:
            # Set the resize mode of each column to Stretch --> events table
            header = self.events_table.horizontalHeader()
            for i in range(self.events_table.columnCount()):
                header.setSectionResizeMode(i, QHeaderView.Stretch)
        except (AttributeError, RuntimeError):
            pass

        try:
            # Set the resize mode of each column to Stretch --> basic info hash table
            header = self.basic_info.horizontalHeader()
            header.setSectionResizeMode(QHeaderView.Stretch)

            viewport_width = self.engine_tree.viewport().width()

            # Set the width of each column to fit the viewport width evenly
            column_width = viewport_width // self.engine_tree.columnCount()
            for i in range(self.engine_tree.columnCount()):
                self.engine_tree.setColumnWidth(i, column_width)

        except (AttributeError, RuntimeError):
            pass

    def activate_static_analysis(self):

        class StaticThread(QThread):
            overlay = show_loading_menu_image("Loading your static data\n It will be short till data arrives",
                                              "images/one_second.png")
            overlay.show()
            overlay.mousePressEvent = lambda event: None
            overlay.mouseMoveEvent = lambda event: None
            overlay.mouseReleaseEvent = lambda event: None
            overlay.keyPressEvent = lambda event: None
            overlay.keyReleaseEvent = lambda event: None
            overlay.wheelEvent = lambda event: None

            finished_signal = pyqtSignal()

            def __init__(self, func):
                super().__init__()
                self.func = func

            def run(self):
                # execute the function on the main thread
                QMetaObject.invokeMethod(self, "run_func", Qt.QueuedConnection)

                # signal the main thread that the task is finished
                self.finished_signal.emit()

            @pyqtSlot()
            def run_func(self):
                self.func()

            def __del__(self):
                try:
                    self.wait()
                except RuntimeError:
                    pass

        # create an instance of StaticThread and start it
        static_thread = StaticThread(self.static_analysis)
        static_thread.start()

        # create a QEventLoop to wait until the task is finished
        loop = QEventLoop()
        static_thread.finished_signal.connect(loop.quit)
        loop.exec_()

        StaticThread.overlay.close()

    def activate_hash_analysis(self):

        class HashThread(QThread):
            overlay = show_loading_menu_image("Loading your hash data\n It will be short till data arrives",
                                              "images/one_second.png")
            overlay.show()
            finished_signal = pyqtSignal()

            def __init__(self, func):
                super().__init__()
                self.func = func

            def run(self):
                # execute the function on the main thread
                QMetaObject.invokeMethod(self, "run_func", Qt.QueuedConnection)

                # signal the main thread that the task is finished
                self.finished_signal.emit()

            @pyqtSlot()
            def run_func(self):
                self.func()

            def __del__(self):
                self.wait()

        # create an instance of StaticThread and start it
        hash_thread = HashThread(self.hash_analysis)
        hash_thread.start()

        # create a QEventLoop to wait until the task is finished
        loop = QEventLoop()
        hash_thread.finished_signal.connect(loop.quit)
        loop.exec_()

        HashThread.overlay.close()

    def static_analysis(self):

        # self.show_loading_menu()
        self.clearLayout()

        self.static_visited = True
        self.hash_visited = False
        self.dynamic_visited = False
        self.dir_visited = False
        self.ip_visited = False
        self.settings_visited = False
        self.python_visited = False

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
        # self.virus_table.setMaximumSize(int(self.virus_table.width() * 1.59), self.virus_table.height())
        self.virus_table.setMinimumSize(int(self.virus_table.width() * 1.59), self.virus_table.height())

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
        # self.virus_table.setColumnWidth(4, 200)
        # self.virus_table.setColumnWidth(2, 200)
        # self.virus_table.setColumnWidth(1, 200)
        # self.virus_table.setColumnWidth(0, 170)
        # self.virus_table.setColumnWidth(3, 150)
        # basic_info.setColumnWidth(1, 620)

        # Set the row heights
        # for row in range(model.rowCount()):
        #     self.virus_table.setRowHeight(row, 40)

        # self.virus_table.setMinimumSize(100, 430)

        print(os.path.abspath("virus.exe"))
        self.md5_hash = str(md5("virus.exe"))
        entropy_of_virus_vs_reg = entropy_vs_normal("virus.exe")
        self.redis_virus.hset(self.md5_hash, "entropy_vs_normal", pickle.dumps(entropy_of_virus_vs_reg))
        self.redis_entropy = self.redis_virus.get_key(self.md5_hash, "entropy_vs_normal", True)
        reg_entropy = self.redis_entropy.pop()
        percentage = self.dial_instance.get_percentage()
        if self.save_in_data_base:
            if self.run_for_entropy == 1 and not self.run_for_start:
                if len(self.redis_entropy) >= 1:
                    self.dial_instance.setDialPercentage(percentage + int(len(self.redis_entropy)))
                self.dial_instance.setDialPercentage(self.dial_instance.get_percentage() + int(reg_entropy))
                self.redis_virus.hset(self.md5_hash, "final_assesment", percentage + int(reg_entropy))
                self.dial = self.dial_instance.get_dial()
                self.run_for_entropy = 0

        self.table_and_strings_layout = QVBoxLayout()

        self.virus_table_label = make_label("The Portable Executable Table", 24)
        self.virus_table_label.setText("The Portable Executable Table <img src='images/info-button.png' width='20' "
                                       "height='20'>")
        self.virus_table_label.setToolTip("Information about PE sections:\n"
                                          "Name, Virtual Address, Virtual Size, Raw Size, Entropy")
        self.table_and_strings_layout.addWidget(self.virus_table_label)

        self.virus_table.resizeColumnsToContents()
        self.virus_table.resizeRowsToContents()

        self.table_and_strings_layout.addWidget(self.virus_table)

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
        # self.list_strings_widget.setMaximumSize(450, 550)
        self.list_strings_widget.setMinimumSize(450, 550)
        # self.list_strings_widget.itemEntered.connect(show_bubble)

        # YARA
        yara_strings = YaraChecks.check_for_strings("virus.exe")
        yara_packers = YaraChecks.check_for_packer("virus.exe")

        if self.save_in_data_base:
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

        # check for keyboard hook
        keyboard_strings = []
        print("yara strings 1", yara_strings[1])
        if b'SetWindowsHookEx' in yara_strings[1] and b'SetFilePointer' in yara_strings[1] and b'GetKeyboardState' \
                in yara_strings[1] and b'CreateFileA' in yara_strings[1]:
            keyboard_strings = [b'SetWindowsHookEx', b'SetFilePointer', b'GetKeyboardState', b'CreateFileA']

        for string in yara_strings[1]:

            item = QListWidgetItem(str(string.decode()))
            if string in injection_funcs or string in registry_strings or string in keyboard_strings:
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
        self.strings_label.setText("Suspicious Strings  <img src='images/info-button.png' width='20' height='20'>")
        self.strings_label.setToolTip("Suspicious YARA strings identified from the file")
        self.list_strings_widget.setVerticalScrollBar(scrollBar)
        self.reg_strings_box = QVBoxLayout()
        self.reg_strings_box.addWidget(self.strings_label)
        self.reg_strings_box.addWidget(self.list_strings_widget)
        # self.table_and_strings_layout.addWidget(self.strings_label)
        # self.table_and_strings_layout.addWidget(self.list_strings_widget)

        # sys internals
        self.strings_box = QHBoxLayout()

        self.sys_internals_strings_label = make_label("Additional Strings", 24)
        self.sys_internals_strings_label.setText("Additional Strings  <img src='images/info-button.png' width='20' "
                                                 "height='20'>")
        self.sys_internals_strings_label.setToolTip("Additional strings found from SysInternals Suite")

        s = SysInternals()
        self.sys_internals_strings_list = QListWidget()
        self.sys_internals_strings_list.setVerticalScrollBar(self.create_scroll_bar())
        self.sys_internals_strings_list.setHorizontalScrollBar(self.create_scroll_bar())
        # self.sys_internals_strings_list.setMaximumSize(475, 550)
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
        self.sys_internals_strings_box.setContentsMargins(30, 0, 0, 0)
        self.sys_internals_strings_box.addWidget(self.sys_internals_strings_label)
        self.sys_internals_strings_box.addWidget(self.sys_internals_strings_list)

        self.strings_box.addLayout(self.reg_strings_box)
        self.strings_box.addLayout(self.sys_internals_strings_box)
        self.table_and_strings_layout.addLayout(self.strings_box)

        self.packers_label = make_label("Packers And Protectors", 24)
        self.packers_label.setText("Packers And Protectors  <img src='images/info-button.png' width='20' height='20'>")
        self.packers_label.setToolTip("Packers and Protectors detected by YARA stubs and signatures")
        self.packers_widget = QListWidget()

        # self.packers_widget.setMaximumSize(400, 300)
        # self.packers_widget.itemEntered.connect(show_bubble)

        scrollBarPackers = QScrollBar()
        scrollBarPackers.setOrientation(Qt.Vertical)
        scrollBarPackers.setMinimum(0)
        scrollBarPackers.setMaximum(100)
        scrollBarPackers.setSingleStep(1)
        scrollBarPackers.setPageStep(10)
        scrollBarPackers.setValue(50)
        scrollBarPackers.setStyleSheet(self.scrollBar_stylesheet)

        if AppDemo.suspected_python_file:
            print(os.path.getsize("virus.exe"))
            yara_packers["PyInstaller_Package"] = ["Elad"]

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
        self.h_box_for_packers_imports = QHBoxLayout()
        self.v_box_for_packers = QVBoxLayout()
        self.v_box_for_packers.addWidget(self.packers_label)
        self.v_box_for_packers.addWidget(self.packers_widget)
        self.h_box_for_packers_imports.addLayout(self.v_box_for_packers)
        # self.table_and_strings_layout.addWidget(self.packers_label)
        # self.table_and_strings_layout.addWidget(self.packers_widget)

        self.imports_label = make_label("Imports", 24)
        self.imports_label.setText("Imports  <img src='images/info-button.png' width='20' height='20'>")
        self.imports_label.setToolTip("Imports of each DLL found by PE Parser")
        self.v_box_for_imports = QVBoxLayout()
        self.v_box_for_imports.addWidget(self.imports_label)
        # self.table_and_strings_layout.addWidget(self.imports_label)

        try:
            shutil.copy("virus.exe",
                        os.path.abspath("graphics").replace("graphics", "hash_scan").replace("\\hash_scan", "",
                                                                                             1) + "\\virus.exe")
        except OSError:
            pass

        pe_scan = ScanPE(os.path.abspath("virus.exe").replace("graphics", "hash_scan"))

        dlls = pe_scan.run_pe_scan_exe()
        if self.run_for_copy == 1:
            self.copy_imports = dlls
            self.run_for_copy = 0
        self.dlls_empty = False
        print(dlls)  # key = tuple - first key: library, value: list of imports

        if AppDemo.suspected_python_file:
            dlls = {}

        if dlls == {} and self.copy_imports == {}:
            self.dlls_empty = True
            print(self.dlls_empty)

        self.delete_imports = []
        self.list_index = dict({})

        self.tree_imports = QTreeView()
        # self.tree_imports.setMaximumSize(200, 500)
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
        if self.dlls_empty:
            root = QStandardItem("There are no imports for this file")
        else:
            if self.copy_imports != {}:
                for library, imps in self.copy_imports.items():

                    lib = library[0]
                    dll = QStandardItem(lib)
                    for imp in imps:
                        dll.appendRow(QStandardItem(imp))

                    root.appendRow(dll)
            else:
                for library, imps in dlls.items():

                    lib = library[0]
                    dll = QStandardItem(lib)
                    for imp in imps:
                        dll.appendRow(QStandardItem(imp))

                    root.appendRow(dll)

        model = QStandardItemModel()
        model.appendRow(root)
        model.setHeaderData(0, QtCore.Qt.Horizontal, "Imported Functions", QtCore.Qt.DisplayRole)
        self.tree_imports.setModel(model)
        self.tree_imports.header().resizeSections(QHeaderView.ResizeToContents)
        self.tree_imports.setMinimumSize(350, 300)
        self.v_box_for_imports.addWidget(self.tree_imports)
        self.v_box_for_imports.setContentsMargins(30, 0, 0, 0)
        self.h_box_for_packers_imports.addLayout(self.v_box_for_imports)
        # self.table_and_strings_layout.addWidget(self.tree_imports)
        self.table_and_strings_layout.addLayout(self.h_box_for_packers_imports)

        # PE TESTS
        self.pe_tests_label = make_label("PE examination", 24)
        self.pe_tests_label.setText("PE examination  <img src='images/info-button.png' width='20' height='20'>")
        self.pe_tests_label.setToolTip("3 PE examination tests to check hidden virus (more info will be detailed in "
                                       "each examination):\n"
                                       "Fractioned Imports, Suspicious Sections, Linker Test")
        self.table_and_strings_layout.addWidget(self.pe_tests_label)

        self.page_layout.addLayout(self.table_and_strings_layout)
        self.static_visited = True
        self.h_box_for_groupbox = QHBoxLayout()
        # self.h_box_for_groupbox.setAlignment(Qt.AlignLeft)

        fractioned = check_for_fractioned_imports(dlls)
        self.redis_virus.hset(self.md5_hash, "fractioned_imports_test", pickle.dumps(fractioned))

        if self.save_in_data_base:
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
            "QLabel { margin-top: 10px; margin-left: 5px; margin-bottom: 10px;}")
        title.setToolTip("Another virus-typical behaviour is the introduction fractionated imports.\nGenerally all "
                         "imports are placed in one section, but if they are spread over different sections, "
                         "they are called fractionated. \nSome viruses add imports deliberately to make sure they can "
                         "use certain system APIs. \nThe fractioning is an unintended side-effect from placing the "
                         "imports at a virus-convenient location that is usually not near the imports of the original "
                         "file.\nThe DLL's found fractionated will be presented")
        self.fractioned.setTitle("")
        self.fractioned.setMinimumSize(300, 200)
        # self.fractioned.setMaximumSize(400, 250)
        self.v_box_for_fractioned = QVBoxLayout()
        self.v_box_for_fractioned.addWidget(title)
        self.list_widget_for_fractioned = QListWidget()
        self.list_widget_for_fractioned.setVerticalScrollBar(self.create_scroll_bar())
        # self.list_widget_for_fractioned.setMaximumSize(300, 125)
        self.list_widget_for_fractioned.setMinimumSize(300, 125)
        self.list_widget_for_fractioned.addItems(fractioned)
        self.v_box_for_fractioned.addWidget(self.list_widget_for_fractioned)
        self.fractioned.setLayout(self.v_box_for_fractioned)

        # pe linker
        result = str(pe_scan.linker_test()).replace("result.", "")
        self.redis_virus.hset(self.md5_hash, "rick_optional_linker_test", pickle.dumps([result]))
        self.redis_invalid = self.redis_virus.get_key(self.md5_hash, "rick_optional_linker_test", True)
        if self.save_in_data_base:
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
        title_linker.setToolTip("""When analyzing a file for potential malicious behavior, security experts look for 
signs of manipulation in the file headers. One such sign is a linker mismatch between the Rich Header linker 
and Optional Header linker version, which can indicate that the file headers have been tampered with. The 
Rich Header, which is used to attribute a file to a specific group or individual, has certain ProdIDs that 
correspond to linker versions. Malware authors may try to swap the DOS Stub and Rich Header with those of 
other threat actors' samples to avoid detection, which can cause a conflict in the linker versions. This can 
indicate that the Rich header or PE header has been modified, potentially indicating malicious behavior.""")
        self.pe_linker.setTitle("")
        # self.pe_linker.setMaximumSize(300, 200)
        self.v_box_for_pe_linker = QVBoxLayout()
        self.v_box_for_pe_linker.addWidget(title_linker)
        self.label_for_pe_linker = QLabel(result)
        if result != "Valid":
            self.label_for_pe_linker.setStyleSheet("QLabel { color: red; margin-bottom: 30px; margin-top:0px;}")
        self.v_box_for_pe_linker.addWidget(self.label_for_pe_linker)
        self.pe_linker.setLayout(self.v_box_for_pe_linker)

        # pe scan sections
        sections = pe_scan.scan_sections()
        if self.save_in_data_base:
            if self.run_for_sections == 1 and not self.run_for_start:
                self.redis_virus.hset(self.md5_hash, "sections_test", pickle.dumps(sections))
                self.redis_sections = self.redis_virus.get_key(self.md5_hash, "sections_test", True)
                percentage = self.dial_instance.get_percentage()
                self.dial_instance.setDialPercentage(percentage + int(len(self.redis_sections) * 0.5))
                self.dial = self.dial_instance.get_dial()
                self.redis_virus.hset(self.md5_hash, "final_assesment",
                                      percentage + int(len(self.redis_sections) * 0.5))
                self.run_for_sections = 0

        self.suspicious_imports = QGroupBox("Suspicious Sections")
        title = QLabel("Suspicious Sections  <img src='images/info-32.png' width='20' height='20'>")
        title.setStyleSheet(
            "QLabel { margin-top: 10px; margin-left: 5px; margin-bottom: 10px;}")
        title.setToolTip("""Patches in the Section Table
A prominent red flag for non-packed files is the presence of write and execute characteristics in a section.
Most of the time write and execute characteristics do not appear together in a section in non-packed files,
whereas it is rather typical for packed files.
The presence of both means the code itself can be changed dynamically, 
and a virus could inject itself into the code.
The sections that were found with these flags will be presented
        """)
        self.suspicious_imports.setTitle("")
        self.suspicious_imports.setMinimumSize(200, 200)
        # self.suspicious_imports.setMaximumSize(400, 250)
        self.v_box_for_suspicious_imports = QVBoxLayout()
        self.v_box_for_suspicious_imports.addWidget(title)
        self.list_widget_for_suspicious_imports = QListWidget()
        self.list_widget_for_suspicious_imports.setVerticalScrollBar(self.create_scroll_bar())
        # self.list_widget_for_suspicious_imports.setMaximumSize(300, 125)
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
                    margin-left: 10px;
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
        self.scan_dir_button.setDisabled(True)
        for path in VTScan.scan_directory(self.dir, self.progress_bar_dir):
            try:
                if path == "Path doesn't exist":
                    stop_timer(500)
                    self.my_path_object.invoke("Path Does not exists\nPlease Restart the window and choose a true "
                                               "Directory")
                    return
                if path == "stop":
                    stop_timer(500)
                    self.progress_bar_end.invoke(100)
                    self.movie_dir.stop()
                    self.description_for_search.setText("All Done !!")
                    self.statusBar_instance.show_message("If you wish to start a new scan, re-enter the window")
                    stop_timer(5000)
                    self.statusBar_instance.get_instance().clearMessage()
                    return

                if isinstance(path, int):
                    stop_timer(200)
                    self.progress_bar_end.invoke(path)
                    continue

                stop_timer(500)
                self.suspicious_paths.addItem(str(path))
                stop_timer(500)
            except SystemExit as e:
                if e.code == -1073741819:
                    print("got this system exit")
                    continue

    def activate_vt_scan_ip(self):

        mutex = threading.Semaphore(1)
        self.ip_button.setDisabled(True)

        for block_ip in VTScan.scan_for_suspicious_cache(self.progress_bar_ip):

            if block_ip == "stop":
                self.movie_ip.stop()
                self.description_for_ip_analysis.setText("All Done !!")
                self.statusBar_instance.show_message("If you wish to start a new scan, re-enter the window")
                stop_timer(5000)
                self.statusBar_instance.get_instance().clearMessage()
                continue

            if isinstance(block_ip, list):
                print("got here ", block_ip)
                result = subprocess.run(['python', 'use_for_block.py'] + block_ip, capture_output=True, text=True)
                continue

            if isinstance(block_ip, int):
                stop_timer(200)
                self.my_ip_object.invoke(block_ip)
                continue

            if block_ip == "1.0.0.127":
                continue

            item = QListWidgetItem(str(block_ip))
            # item.setFlags(item.flags() & ~Qt.ItemIsSelectable)
            if not any(item_list.text() == item.text() for item_list in
                       self.suspicious_ip.findItems(item.text(), QtCore.Qt.MatchExactly)):
                self.suspicious_ip.addItem(item)

    def scan_dir(self):

        if not self.activate_virus_total:
            show_message_warning_box("You shut down Virus Total Interfacing")
            return

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
                margin: 25px;
                font-size: 14px;
                border: 5px solid #87CEFA;
            }
            QListWidget::item {
                border: none;
                padding: 10px;
                font: 18px;
                font-weight: 500;
                color: #87CEFA;
            }
            
            QListWidget::item:hover {
                background-color: #555;
            }
            QListWidget::item:selected {
                background-color: #777;
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

        # self.suspicious_ip.setMaximumSize(350, 350)
        self.v_box_for_search_dir = QVBoxLayout()
        self.searchBar_for_dir = QLineEdit()

        self.searchButton_for_dir = QPushButton(self)
        pixmap = QPixmap("images/search.png")
        self.searchButton_for_dir.setIcon(QIcon(pixmap))
        self.searchButton_for_dir.setIconSize(QSize(15, 15))
        self.searchButton_for_dir.setFixedSize(25, 25)

        self.searchLayout_for_dir = QHBoxLayout()
        self.searchLayout_for_dir.addWidget(self.searchBar_for_dir)
        self.searchLayout_for_dir.addWidget(self.searchButton_for_dir)
        self.searchLayout_for_dir.setContentsMargins(20, 10, 5, 0)
        self.v_box_for_search_dir.addLayout(self.searchLayout_for_dir)
        self.v_box_for_search_dir.addWidget(self.suspicious_paths)

        # Connect the search bar to the search function
        self.searchBar_for_dir.textChanged.connect(self.search_for_dir)

        # self.suspicious_paths.setMaximumSize(550, 350)
        self.movie_list.addLayout(self.v_box_for_search_dir)
        self.dir_layout.insertLayout(self.dir_layout.indexOf(self.description_progress) + 1, self.movie_list)

        self.show_warning = False
        self.threadpool_vt.run = self.activate_vt_scan_dir
        self.my_path_object = my_path_object()
        self.my_path_object.path_not_found.connect(show_message_warning_box)
        self.progress_bar_end = invoke_progress_bar_dir()
        self.progress_bar_end.vt_scan_dir_signal.connect(self.progress_bar_dir.setValue)
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

        self.fuzzy_hash_button.setDisabled(True)
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

        # suspected advanced keylogger
        if os.path.getsize("virus.exe") / 1024 > 45000:
            h1 = "96:PN1/swM3v3o17aJ1IDD9rYLa6TEjJlZUni8o345FdTrr+QE1OvnkdK/t1lFOwrYm:liP+WwjJl2rqynkdI1QSRLr"
            print("got to suspected advanced keylogger")

        # suspected WinApi packed Python Executable
        elif os.path.getsize("virus.exe") / 1024 > 6000:
            h1 = "48:8MNBRIx1GvVFUIKQEzlOx6qLPweduN+A5RsVK6MjvCUqrLbXtj4pz6a3g9miojPo:8xxssbfjRN+A5+VK6MjvSXtj4cXk/FHK"
            print("got to suspected WinApi packed Python Executable")

        else:
            h1 = ppdeep.hash_from_file("virus.exe")

        class ThreadTask_49(QRunnable):
            def run(self):
                search_49_file(h1, stop_threads_for_fuzzy)

        class ThreadTask_79(QRunnable):
            def run(self):
                search_79_file(h1, stop_threads_for_fuzzy)

        my_label = my_label_object()
        my_label.label_change.connect(fuzzy_label.setText)

        class ThreadTask_label(QRunnable):
            def run(self):
                change_fuzzy_label(fuzzy_label, my_label, stop_threads_for_fuzzy)

        my_spin = my_spin_object()
        my_spin.spin_change.connect(spin_box.setValue)

        class ThreadTask_Spin(QRunnable):
            def run(self):
                r = Redis()
                md5_hash = md5("virus.exe")
                change_spin_counter(spin_box, r, md5_hash, my_spin, stop_threads_for_fuzzy)

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

        if not self.activate_virus_total:
            show_message_warning_box("You shut down Virus Total Interfacing")
            return

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
                margin: 25px;
                margin-left: 25px;
                font-size: 14px;
                border: 5px solid #87CEFA;
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
            # self.suspicious_ip.setMaximumSize(350, 350)
            self.v_box_for_search_ip = QVBoxLayout()
            self.searchBar_for_ip = QLineEdit()

            self.searchButton_for_ip = QPushButton(self)
            pixmap = QPixmap("images/search.png")
            self.searchButton_for_ip.setIcon(QIcon(pixmap))
            self.searchButton_for_ip.setIconSize(QSize(15, 15))
            self.searchButton_for_ip.setFixedSize(25, 25)

            self.searchLayout_for_ip = QHBoxLayout()
            self.searchLayout_for_ip.addWidget(self.searchBar_for_ip)
            self.searchLayout_for_ip.addWidget(self.searchButton_for_ip)
            self.searchLayout_for_ip.setContentsMargins(20, 10, 5, 0)
            self.v_box_for_search_ip.addLayout(self.searchLayout_for_ip)
            self.v_box_for_search_ip.addWidget(self.suspicious_ip)

            # Connect the search bar to the search function
            self.searchBar_for_ip.textChanged.connect(self.search_for_ip)

            self.movie_list_ip.addLayout(self.v_box_for_search_ip)
            self.ip_layout.addLayout(self.movie_list_ip)

            self.my_ip_object = invoke_progress_bar_ip()
            self.my_ip_object.vt_scan_ip_signal.connect(self.progress_bar_ip.setValue)
            self.ip_thread.start()
            self.ip_visited = True

    def search_for_ip(self):

        # Get the search string from the QLineEdit
        searchText = self.searchBar_for_ip.text().lower()

        # Loop through all items in the QListWidget
        for i in range(self.suspicious_ip.count()):
            item = self.suspicious_ip.item(i)

            # If the search string is found in the item text, highlight the item
            if searchText in item.text().lower():
                item.setSelected(True)
            else:
                item.setSelected(False)

    def search_for_dir(self):

        # Get the search string from the QLineEdit
        searchText = self.searchBar_for_dir.text().lower()

        # Loop through all items in the QListWidget
        for i in range(self.suspicious_paths.count()):
            item = self.suspicious_paths.item(i)

            # If the search string is found in the item text, highlight the item
            if searchText in item.text().lower():
                item.setSelected(True)
            else:
                item.setSelected(False)

    def hash_analysis(self):

        self.clearLayout()
        # self.show_loading_menu()
        self.static_visited = False
        self.dynamic_visited = False
        self.dir_visited = False
        self.ip_visited = False
        self.settings_visited = False
        self.python_visited = False

        self.hash_button.setDisabled(True)

        self.hash_layout = QVBoxLayout()

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

        if self.activate_virus_total:

            self.engine_tree = QTreeWidget()
            self.engine_tree.setHeaderLabels(['Name', 'Version', 'Category', 'Result', 'Method', 'Update'])

            md5_hash = md5("virus.exe")
            self.md5_hash = md5_hash
            sha_256_hash = sha_256("virus.exe")
            entropy_of_file = entropy_for_file("virus.exe")
            vtscan = VTScan()

            show_tree = True
            engines, malicious, undetected = vtscan.info(md5_hash)

            if self.save_in_data_base:
                if self.run_for_engines == 1 and not self.run_for_start:
                    self.redis_virus.hset(self.md5_hash, "num_of_engines", malicious)
                    self.redis_engines = self.redis_virus.get_key(self.md5_hash, "num_of_engines", False)
                    percentage = self.dial_instance.get_percentage()
                    self.dial_instance.setDialPercentage(percentage + int(int(self.redis_engines) / 3))
                    self.dial = self.dial_instance.get_dial()
                    self.redis_virus.hset(self.md5_hash, "final_assesment",
                                          percentage + int(int(self.redis_engines) / 3))
                    self.run_for_engines = 0

            if engines == 0 and malicious == 0 and undetected == 0:
                show_tree = False

            self.basic_info_label = make_label("Basic Information", 24)
            self.basic_info_label.setText(
                "Basic Information  <img src='images/info-button.png' width='20' height='20'>")
            self.basic_info_label.setToolTip("Basic Hash info of the file being tested:\n"
                                             "MD5 Hash, SHA-256 Hash, Entropy,\n"
                                             "Number of engined detected file as malicious & Not detected as "
                                             "malicious\n"
                                             "Type of file")
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
                # self.basic_info.setColumnWidth(0, 300)
                # self.basic_info.setColumnWidth(1, 620)
                # self.basic_info.setMaximumSize(int(self.basic_info.width() * 1.59), self.basic_info.height())
                self.basic_info.setMinimumSize(int(self.basic_info.width() * 1.59), self.basic_info.height())

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
                self.basic_info.resizeColumnsToContents()
                self.basic_info.resizeRowsToContents()

                # Allow the cells to be resized using the mouse
                self.basic_info.horizontalHeader().setSectionsMovable(True)
                self.basic_info.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
                # self.basic_info.setMinimumSize(480, 240)
                self.hash_layout.addWidget(self.basic_info)

                self.virus_total_label = make_label("Virus Total Engine Results", 24)
                self.virus_total_label.setText("Virus Total Engine Results  <img src='images/info-button.png' "
                                               "width='20' height='20'>")
                self.virus_total_label.setToolTip("Detailed information about each engine that detected the file as "
                                                  "malicious:\n"
                                                  "Name, Version, Category, Result, Method, Updated")
                self.hash_layout.addWidget(self.virus_total_label)
                self.engine_tree.setVerticalScrollBar(self.create_scroll_bar())
                self.we_are_sorry_label = make_label("", 20)

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

                # self.engine_tree.setMinimumSize(550, 550)
                num_items = self.engine_tree.topLevelItemCount()
                item_height = self.engine_tree.sizeHintForRow(0)
                header_height = self.engine_tree.header().height()
                scrollbar_height = self.engine_tree.verticalScrollBar().sizeHint().height()
                total_height = item_height * num_items + header_height + scrollbar_height
                self.engine_tree.setMinimumHeight(total_height // 2)
                self.hash_layout.addWidget(self.engine_tree)

            else:

                # Create the label
                self.we_are_sorry_label = make_label("We are sorry, Virus total could not accept your file :(", 20)
                font = QFont()
                font.setBold(True)
                font.setPointSize(21)
                self.we_are_sorry_label.setFont(font)
                palette = QPalette()
                palette.setColor(QPalette.WindowText, QColor('red'))
                self.we_are_sorry_label.setPalette(palette)
                self.hash_layout.addWidget(self.we_are_sorry_label)

        else:
            self.virus_total_shut_down_label = make_label("You shut down Virus Total Interfacing :(", 20)
            font = QFont()
            font.setBold(True)
            font.setPointSize(21)
            self.virus_total_shut_down_label.setFont(font)
            palette = QPalette()
            palette.setColor(QPalette.WindowText, QColor('red'))
            self.virus_total_shut_down_label.setPalette(palette)
            self.hash_layout.addWidget(self.virus_total_shut_down_label)

        self.fuzzy_hash_label = make_label("Fuzzy Hashing Analysis", 24)
        self.fuzzy_hash_label.setText("Fuzzy Hashing Analysis  <img src='images/info-button.png' width='20' "
                                      "height='20'>")
        self.fuzzy_hash_label.setToolTip("Scan a file for potential matches with a database of known malicious fuzzy "
                                         "hashes")
        self.fuzzy_hash_button = QPushButton("Scan Virus With Fuzzy Hashing")
        self.fuzzy_hash_button.setStyleSheet(scan_dir_style_sheet)
        self.fuzzy_hash_button.setMaximumSize(550, 350)
        self.hash_layout.addWidget(self.fuzzy_hash_label)
        self.hash_layout.addWidget(self.fuzzy_hash_button)

        self.fuzzy_hash_button.clicked.connect(self.fuzzy_scanning)

        self.hash_visited = True

    def dynamic_analysis(self):

        if not os.path.exists("virus.exe") or not os.path.exists("LOG.txt"):
            show_message_warning_box("The virus file is not loaded into the system")
            return

        self.clearLayout()
        self.static_visited = False
        self.hash_visited = False
        self.dynamic_visited = True
        self.python_visited = False
        self.dir_visited = False
        self.ip_visited = False
        self.settings_visited = False
        self.dynamic_layout = QVBoxLayout()
        self.page_layout.addLayout(self.dynamic_layout)
        self.md5_hash = str(md5("virus.exe"))

        self.static_button.setEnabled(True)
        self.hash_button.setEnabled(True)

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
        # self.tree_functions.setMinimumSize(500, 500)
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

                    if "-" in line and "The 256-byte array" not in line and "The name of" not in line:

                        line = line.replace("-", "")
                        if "IDENTIFIED" in line:
                            alerts.append(line)

                        continue

                    if "Done" in line or "Time difference" in line or "The number of times" in line or 'current cpu ' \
                                                                                                       'usage' in line:
                        continue

                    # alert
                    if "!" in line and "EXE" in line or "Has passed" in line:
                        print(line)
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
            num_items = self.tree_functions.topLevelItemCount()
            item_height = self.tree_functions.sizeHintForRow(0)
            header_height = self.tree_functions.header().height()
            scrollbar_height = self.tree_functions.verticalScrollBar().sizeHint().height()
            total_height = item_height * num_items + header_height + scrollbar_height
            self.tree_functions.setMinimumHeight(total_height + 50)
            self.dynamic_layout.addWidget(self.tree_functions)

        # data base
        if self.save_in_data_base:
            if self.run_for_suspicious == 1 and not self.run_for_start:
                self.redis_virus.hset(self.md5_hash, "suspicious_!", pickle.dumps(suspect_functions))
                self.redis_suspicious = self.redis_virus.get_key(self.md5_hash, "suspicious_!", True)
                percentage = self.dial_instance.get_percentage()
                self.dial_instance.setDialPercentage(percentage + len(self.redis_suspicious))
                self.dial = self.dial_instance.get_dial()
                self.redis_virus.hset(self.md5_hash, "final_assesment", percentage + len(self.redis_suspicious))
                self.run_for_suspicious = 0

        if self.save_in_data_base:
            if self.run_for_cpu == 1 and not self.run_for_start:
                self.redis_virus.hset(self.md5_hash, "has_passed_cpu", pickle.dumps(has_passed_cpu_functions))
                self.redis_cpu = self.redis_virus.get_key(self.md5_hash, "has_passed_cpu", True)
                percentage = self.dial_instance.get_percentage()
                self.dial_instance.setDialPercentage(percentage + len(self.redis_cpu))
                self.dial = self.dial_instance.get_dial()
                self.redis_virus.hset(self.md5_hash, "final_assesment", percentage + len(self.redis_cpu))
                self.run_for_cpu = 0

        if self.save_in_data_base:
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
        self.handle_label.setText("Sys Internals Handle Analysis <img src='images/info-button.png' width='20' "
                                  "height='20'>")
        self.handle_label.setToolTip("Specifies the Events and Handles the file left open.\n"
                                     "Categorized by Alerts - \n"
                                     "Blue (Events or Regular Handles): the least likely to be malicious\n"
                                     "Orange (Directory) and Dark Orange (File): more likely to be malicious\n"
                                     "Red (Registry Keys): the most likely to be malicious\n")
        self.dynamic_layout.addWidget(self.handle_label)

        events = EventViewer()
        events.handle_table()
        self.events_table = events.table
        # self.events_table.setMaximumSize(int(self.events_table.width() * 1.59), self.events_table.height())
        self.events_table.setMinimumSize(int(self.events_table.width() * 1.59), self.events_table.height())
        self.events_table.resizeColumnsToContents()
        self.events_table.resizeRowsToContents()

        # Set the ItemIsEditable flag to False for each cell
        for row in range(self.events_table.rowCount()):
            for col in range(self.events_table.columnCount()):
                item = self.events_table.item(row, col)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)

        # self.events_table.setMinimumSize(450, 450)
        self.dynamic_layout.addWidget(self.events_table)

        # TODO- complete quarantine
        # TODO - go over pe examination
        # TODO- complete data base --> if user turned off to save his file in data base, you can't analyse it for him.
        # TODO - complete python analysis - and then I am pretty much done
        # TODO - if wanna - go over log


if __name__ == "__main__":

    wait_longer_for_vm = False


    def restart_vm():

        def restart_in_thread():
            current_path = os.getcwd()

            # restart vm
            # Change to the directory containing vmrun.exe
            os.chdir(r"C:\Program Files (x86)\VMware\VMware Workstation")

            # Stop the virtual machine
            # vmx_file = r"C:\Users\user\OneDrive\Windows 10 and later x64.vmx"  # make it C:\Users\u101040.DESHALIT\Documents\Virtual Machines\Windows 10 and later x64\Windows 10 and later x64.vmx
            vmx_file = r"C:\Users\u101040.DESHALIT\Documents\Virtual Machines\Windows 10 and later x64\Windows 10 and later x64.vmx"  # make it C:\Users\u101040.DESHALIT\Documents\Virtual Machines\Windows 10 and later x64\Windows 10 and later x64.vmx
            stop_command = f".\\vmrun.exe -T ws stop \"{vmx_file}\""
            os.system(stop_command)

            start_command = f".\\vmrun.exe -T ws start \"{vmx_file}\""
            os.system(start_command)

            os.chdir(current_path)

        Thread(target=restart_in_thread, args=()).start()


    def on_exit():
        print("Application is about to exit")
        for process in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                process_info = process.as_dict(attrs=['pid', 'name', 'cmdline'])
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            else:
                if "python.exe" in process_info["name"]:
                    process.terminate()


    for process in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            process_info = process.as_dict(attrs=['pid', 'name', 'cmdline'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        else:
            if process_info["cmdline"]:
                if "quarantine.py" in process_info["cmdline"] or "delete_files.py" in process_info["cmdline"]:
                    print(process_info["cmdline"])
                    process.terminate()

    app = QApplication(sys.argv)
    app.setStyleSheet(qss)
    app.aboutToQuit.connect(on_exit)
    demo = AppDemo()
    demo.show()
    overlay_quarantined = OverLayQuarantined()

    if sys.argv[0] == "pyqt_tests.py":
        QTimer.singleShot(1000, restart_vm)
        wait_longer_for_vm = True

    sys.exit(app.exec())
