import os
import sys

from PyQt5 import QtCore
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

from poc_start.unrelated.graphics.quarantine import Quarantine


def stop_timer(time):
    timer = QTimer()
    timer.start(time)
    loop = QEventLoop()
    timer.timeout.connect(loop.quit)
    loop.exec_()


class my_path_object(QObject):
    path_not_found = pyqtSignal(str)

    def __init__(self):
        super().__init__()

    def invoke(self, message):
        self.path_not_found.emit(message)


class invoke_progress_bar_dir(QObject):
    vt_scan_dir_signal = pyqtSignal(int)

    def __init__(self):
        super().__init__()

    def invoke(self, value):
        self.vt_scan_dir_signal.emit(value)


class invoke_progress_bar_ip(QObject):
    vt_scan_ip_signal = pyqtSignal(int)

    def __init__(self):
        super().__init__()

    def invoke(self, value):
        self.vt_scan_ip_signal.emit(value)


def show_message_warning_box(message, on_close_func=None):
    message_box_error = QMessageBox()
    message_box_error.setIcon(QMessageBox.Warning)
    message_box_error.setWindowTitle("Warning")
    message_box_error.setText(message)

    # Set the stylesheet for the message box
    message_box_error.setStyleSheet("QMessageBox {"
                                    "background-color: #333;"
                                    "border: 2px solid #444;"
                                    "}"
                                    "QMessageBox QLabel {"
                                    "color: #87CEFA;"
                                    "font-size: 14px;"
                                    "font-weight: bold;"
                                    "}"
                                    "QMessageBox QPushButton {"
                                    "color: #fff;"
                                    "background-color: #87CEFA;"
                                    "border: none;"
                                    "padding: 10px;"
                                    "font-size: 14px;"
                                    "}"
                                    "QMessageBox QPushButton:hover {"
                                    "background-color: #4682B4;"
                                    "}")

    # Connect on_close_func to the accepted() and rejected() signals of the message box
    if on_close_func is not None:
        message_box_error.accepted.connect(on_close_func)
        message_box_error.rejected.connect(on_close_func)

    # Display the message box
    message_box_error.exec_()
    return


class MessageBox(QDialog):

    def __init__(self, title, message, message_type='warning', parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)

        # Set up the layout
        layout = QVBoxLayout()

        # Add the message icon and label
        if message_type == 'warning':
            self.setWindowIcon(QIcon('images/warning_icon.png'))
        elif message_type == 'info':
            self.setWindowIcon(QIcon('images/info_icon.png'))
        elif message_type == 'error':
            self.setWindowIcon(QIcon('images/error_icon.png'))

        message_label = QLabel(message)
        message_label.setAlignment(Qt.AlignCenter)
        message_label.setStyleSheet('font-size: 28px; font-weight: bold; color: #333; margin-bottom: 15px;')
        layout.addWidget(message_label)

        # Add some padding
        layout.setContentsMargins(25, 25, 25, 25)

        # Add the OK button
        ok_button = QPushButton('OK')
        ok_button.clicked.connect(self.accept)
        ok_button.setStyleSheet('''
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 5px;
                padding: 10px 20px;
                font-size: 20px;
            }
            QPushButton:hover {
                background-color: #1E88E5;
            }
            QPushButton:pressed {
                background-color: #1976D2;
            }
        ''')
        layout.addWidget(ok_button)

        # Set the layout
        self.setLayout(layout)

        # Set the stylesheet
        self.setStyleSheet('''
            QDialog {
                background-color: #f2f2f2;
                border: none;
                border-radius: 10px;
                font-family: Arial, sans-serif;
                font-size: 14px;
            }

            QDialog QLabel {
                color: #333;
                font-weight: bold;
                margin-bottom: 10px;
            }

            QDialog QPushButton {
                background-color: #007bff;
                border: none;
                border-radius: 5px;
                color: #fff;
                padding: 8px 16px;
            }

            QDialog QPushButton:hover {
                background-color: #0056b3;
                cursor: pointer;
            }
        ''')

    def show_dialog(self):
        self.exec_()


class StatusBar:

    def __init__(self):
        self.statusBar = QStatusBar()
        self.statusBar.setStyleSheet("""
                    QStatusBar {
                        border: 1px solid #ccc;
                        background-color: #333;
                        color: #87CEFA;
                        font-size: 16px;
                        font-weight: bold;
                    }
                    QStatusBar::item {
                        border: none;
                    }
                    QStatusBar QLabel {
                        color: #87CEFA;
                        font-size: 18px;
                        font-weight: bold;
                        padding-left: 10px;
                    }
                    QStatusBar QLabel#statusMessage {
                        color: #87CEFA;
                        font-size: 18px;
                        font-weight: bold;
                        padding-left: 10px;
                    }
                """)

    def get_instance(self):
        return self.statusBar

    def show_message(self, message):
        self.statusBar.showMessage(message)
        self.timer = QTimer()
        self.timer.timeout.connect(self.hide_status_message)
        self.timer.start(5000)  # hide message after 5 seconds

    def hide_status_message(self):
        self.timer.stop()
        self.statusBar.clearMessage()

    def show_few(self, messages):
        self.statusBar.clearMessage()
        timer = QTimer()
        timer.setInterval(5000)  # set the interval to 5 seconds
        index = 0

        def show_message():
            nonlocal index
            if index < len(messages):
                message = messages[index]
                self.statusBar.showMessage(message)
                index += 1
            else:
                timer.stop()
                self.statusBar.clearMessage()

        timer.timeout.connect(show_message)
        show_message()
        timer.start()


class worker_for_function(QObject):
    finished_function = pyqtSignal()

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs

    @pyqtSlot()
    def do_work(self):
        print("got to do work")
        self.func(*self.args, **self.kwargs)
        self.finished_function.emit()


def show_loading_menu(message):
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
            self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
            # self.setAttribute(QtCore.Qt.WA_TranslucentBackground)

            # Create the label for the gif
            self.label_load = QLabel()
            movie = QMovie("loading.gif")
            self.label_load.setMovie(movie)

            # Create the label for the text
            self.text_label = QLabel(message)
            self.label_load.setAlignment(Qt.AlignCenter)

            # Style the text label
            font = QFont()
            font.setFamily("Zapfino")
            font.setPointSize(16)
            font.setBold(True)
            self.text_label.setFont(font)
            self.text_label.setStyleSheet("color: #0096FF;")
            self.text_label.setAlignment(Qt.AlignCenter)

            # Create the main layout
            self.layout_load = QVBoxLayout()
            self.layout_load.addWidget(self.label_load, 0, Qt.AlignCenter)
            self.layout_load.addWidget(self.text_label, 0, Qt.AlignBottom)

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

    overlay = OverlayWindow()
    print("got to overlay")
    return overlay


def show_loading_menu_image(message, image_path):
    # self.clearLayout()

    class OverlayWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.initUI()

        def initUI(self):
            self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
            # self.setAttribute(QtCore.Qt.WA_TranslucentBackground)

            # Create the label for the image
            self.label_image = QLabel()
            pixmap = QPixmap(image_path)
            self.label_image.setPixmap(pixmap)
            self.label_image.setAlignment(Qt.AlignCenter)

            # Create the label for the text
            self.text_label = QLabel(message)
            self.text_label.setAlignment(Qt.AlignCenter)

            # Style the text label
            font = QFont()
            font.setFamily("Zapfino")
            font.setPointSize(16)
            font.setBold(True)
            self.text_label.setFont(font)
            self.text_label.setStyleSheet("color: #0096FF;")

            # Create the main layout
            self.layout_load = QVBoxLayout()
            self.layout_load.addWidget(self.label_image, 0, Qt.AlignCenter)
            self.layout_load.addWidget(self.text_label, 0, Qt.AlignBottom)

            central_widget = QWidget(self)
            central_widget.setLayout(self.layout_load)
            self.setCentralWidget(central_widget)

            # Set the position of the window to the center of the screen
            frame_geo = self.frameGeometry()
            screen_center = QDesktopWidget().availableGeometry().center()
            frame_geo.moveCenter(screen_center)
            self.move(frame_geo.topLeft())

    overlay = OverlayWindow()
    return overlay


# class Wait_For_Data(QThread):
#     overlay = show_loading_menu("Uploading your data...\nThis will take just a second")
#     overlay.show()
#     finished_signal = pyqtSignal()
#
#     def __init__(self, func):
#         super().__init__()
#         self.func_to_run = func
#
#     def run(self):
#         self.func_to_run()
#
#         # signal the main thread that the task is finished
#         self.finished_signal.emit()


class CustomDialStyle(QProxyStyle):
    def drawComplexControl(self, control, option, painter, widget=None):
        if control == QStyle.CC_Dial and widget and isinstance(widget, QDial):
            # Disable the default drawing of the dial control
            option.state &= ~QStyle.State_Enabled
            # Set the palette to use for the dial control
            palette = widget.palette()
            if not widget.isEnabled():
                palette.setColor(QPalette.Button, palette.color(QPalette.Window))
            # Draw the dial control using the new options
            QProxyStyle.drawComplexControl(self, control, option, painter, widget)
        else:
            # Draw other controls using the default options
            QProxyStyle.drawComplexControl(self, control, option, painter, widget)


class DialWatch(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # Create a dial widget
        self.dial = QDial()
        self.dial.setRange(0, 99)
        self.dial.setFixedSize(100, 100)
        self.dial.setStyleSheet("border-radius: 25px; margin-right: 25px;")

        self.dial.mousePressEvent = lambda event: None
        self.dial.mouseMoveEvent = lambda event: None
        self.dial.mouseReleaseEvent = lambda event: None
        self.dial.keyPressEvent = lambda event: None
        self.dial.keyReleaseEvent = lambda event: None
        self.dial.wheelEvent = lambda event: None

        self.dial.setNotchesVisible(True)
        self.dial.notchSize = 20
        self.dial.valueChanged.connect(self.onDialChanged)

        self.setDialColor(0)

    def get_dial(self):
        return self.dial

    def onDialChanged(self, value):
        percentage = value + 1
        self.setDialColor(percentage)

    def setDialPercentage(self, percentage):
        if percentage >= 99:
            percentage = 99
        self.dial.setValue(percentage - 1)
        self.setDialColor(percentage)

    def get_percentage(self):
        return self.dial.value() + 1

    def setDialColor(self, percentage):
        # Calculate the color based on the percentage
        red = int(255 * percentage / 100)
        green = int(255 * (100 - percentage) / 100)
        blue = 0

        # Create a new palette with the calculated color
        palette = QPalette()
        palette.setColor(QPalette.Button, QColor(red, green, blue))

        # Set the new palette to the dial widget
        self.dial.setPalette(palette)


class EventViewer():
    def __init__(self):
        self.path = os.path.abspath("sys_internals").replace("\graphics", "") + "\output_handles.txt"
        super().__init__()

        # Create table widget
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Number", "Event", "Permissions", "Resources"])

        # Left-align the headers
        header = self.table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeft)

        with open("css_files/handle_table.css", "r") as f:
            self.table.setStyleSheet(f.read())

    def handle_table(self):

        with open(self.path, "r") as f:

            handle_data = f.read()
            for line in handle_data.split("\n"):
                data = line.split(" ")

                if data[0] == "":
                    data = [i for i in data if i != ""]
                    if data:
                        number = data[0]
                        type = data[1]
                        color = QColor()
                        color.setNamedColor("#87CEFA")
                        if type == "Directory":
                            color = "orange"
                        if type == "File":
                            color = "darkOrange"
                        if type == "Key":
                            color = "red"

                        perm = "----"
                        resources = "----"
                        if len(data) >= 3:
                            resources = ""
                            if "(" in data[2]:
                                perm = data[2]
                            for resource in data[2:]:
                                if "(" in resource or "--" in resource or "RW" in resource:
                                    continue
                                resources += resource
                                resources += "\n"

                        self.add_event(number, type, perm, resources, color)

    def add_event(self, number, type, perm, resource, color):

        if color == "darkOrange":
            color = QColor(255, 100, 0)
        else:
            color = QColor(color)

        # Add a new row to the table
        row_position = self.table.rowCount()
        self.table.insertRow(row_position)

        # Add the data to the table cells
        number_item = QTableWidgetItem(number)
        number_item.setForeground(QBrush(color))
        number_item.setFlags(number_item.flags() & ~Qt.ItemIsSelectable)
        self.table.setItem(row_position, 0, number_item)

        type_item = QTableWidgetItem(type)
        type_item.setFlags(type_item.flags() & ~Qt.ItemIsSelectable)
        type_item.setForeground(QBrush(color))
        self.table.setItem(row_position, 1, type_item)

        permission_item = QTableWidgetItem(perm)
        permission_item.setForeground(QBrush(color))
        permission_item.setFlags(permission_item.flags() & ~Qt.ItemIsSelectable)
        self.table.setItem(row_position, 2, permission_item)

        resource_item = QTableWidgetItem(resource)
        resource_item.setForeground(QBrush(color))
        resource_item.setFlags(resource_item.flags() & ~Qt.ItemIsSelectable)

        for row in range(self.table.rowCount()):
            item = self.table.item(row, 3)  # get item in the fourth column
            if item is not None:
                self.table.setRowHeight(row, 80)  # set row height to 50 pixels

        self.table.setItem(row_position, 3, resource_item)


def write_text_file_without_line(path, line, original_data):
    with open(path, "w") as f:
        for line_file in original_data.split("\n"):
            if line.strip() == line_file.strip():
                continue
            f.write(line_file)


class OverLayQuarantined(QMainWindow):
    closed = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.table = QTableWidget(self)
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["Name", "Date"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)  # Prevent editing cells
        self.table.setShowGrid(False)  # Hide gridlines
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.table.horizontalHeader().setFixedHeight(30)
        self.table.verticalHeader().setStyleSheet('background-color: #555; color: #fff;')
        self.table.verticalHeader().setFixedWidth(30)
        self.table.setStyleSheet("""
                    QTableWidget {
                font-family: sans-serif;
                font-size: 18px;
                color: #87CEFA;
                background-color: #333;
                border: 2px solid #444;
                gridline-color: #666;
            }
            
            QTableWidget::item {
                padding: 20px;
                margin: 20px;
                min-width: 100px;
                min-height: 20px;
                font-weight: bold;
            }
            
            QTableWidget::header {
                font-size: 24px;
                font-weight: bold;
                background-color: #444;
                border-bottom: 2px solid #555;
                min-height: 40px;
                color: #fff;
            }
            
            QTableWidget::horizontalHeader {
                border-right: 2px solid #555;
            }
            
            QTableWidget::verticalHeader {
                border-bottom: 2px solid #555;
                color: #fff;
                background-color: #555;
            }
            
            QTableWidget::corner {
                border-right: 2px solid #555;
                border-bottom: 2px solid #555;
                background-color: #555;
            }
            QTableView::item:selected {
                color: #fff;
            }
        """)

        # Connect signal to slot to detect when a row is selected
        self.table.itemSelectionChanged.connect(self.handleSelection)

        self.resize(500, 275)

        # Create the title label
        title_label = self.createTitleLabel("Quarantine Data\nChoose a file to restore")

        # Create the layout and add the widgets to it
        layout = QVBoxLayout()
        layout.addWidget(title_label)
        layout.addWidget(self.table)

        # Set the layout for the main window
        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        close_button = QPushButton('X', self)
        close_button.setFixedSize(20, 20)

        def close():
            self.closed.emit()
            self.close()

        close_button.clicked.connect(lambda: close())

        self.name_to_quarantine = None
        self.date_to_quarantine = None

    def mousePressEvent(self, event):
        self.offset = event.pos()

    def add_data(self):
        self.table.setRowCount(0)
        with open("quarantine_data.txt", "r") as f:
            data = [line.strip().split("|")[2:] for line in f.readlines()]
            data = [l for l in data if l != []]
        for row in data:
            name_item = QTableWidgetItem(row[0])
            date_item = QTableWidgetItem(row[1])
            self.table.insertRow(self.table.rowCount())
            self.table.setItem(self.table.rowCount() - 1, 0, name_item)
            self.table.setItem(self.table.rowCount() - 1, 1, date_item)
        self.table.resizeColumnsToContents()

    def mouseMoveEvent(self, event):
        x = event.globalX()
        y = event.globalY()
        x_w = self.offset.x()
        y_w = self.offset.y()
        self.move(x - x_w, y - y_w)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.close()

    def createTitleLabel(self, text):
        # Create the label widget
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

        # Add padding to the label
        label.setContentsMargins(10, 10, 10, 10)

        return label

    def get_index_by_line(self, filename, search_line):
        with open(filename, 'r') as f:
            for i, line in enumerate(f):
                if line.strip() == search_line.strip():
                    return i  # return the index of the matching line
        return None  # return None if the specified line is not found in the file

    def handleSelection(self):
        selected_row = self.table.currentRow()
        if selected_row >= 0:
            self.name_to_quarantine = self.table.item(selected_row, 0).text()
            self.date_to_quarantine = self.table.item(selected_row, 1).text()
            self.hash = 0

            with open("quarantine_data.txt", "r") as f:
                data = f.read()
                for line in data.split("\n"):
                    if self.name_to_quarantine in line and self.date_to_quarantine in line:
                        self.hash = line.split("|")[0]
                        full_original_path = line.split("|")[1]
                        if os.path.exists(os.path.dirname(full_original_path) + fr"\Found_Virus\{self.name_to_quarantine}"):
                            Quarantine.restore_quarantined_to_original(
                                os.path.dirname(full_original_path) + fr"\Found_Virus\{self.name_to_quarantine}",
                                full_original_path, "1234")
                            write_text_file_without_line("quarantine_data.txt", line, data)
                            break

                for line in data.split("\n"):
                    if self.hash in line:
                        write_text_file_without_line("quarantine_data.txt", line, data)

                self.closed.emit()
                self.close()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    overlay = OverLayQuarantined()
    sys.exit(app.exec_())
