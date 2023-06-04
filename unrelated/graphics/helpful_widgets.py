import os
import sys

from PyQt5 import QtCore
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

from poc_start.unrelated.graphics.quarantine import Quarantine


def stop_timer(time):
    """
    Stops the timer after the specified duration.

    Args:
        time (int): Duration in milliseconds.
    """
    timer = QTimer()
    timer.start(time)
    loop = QEventLoop()
    timer.timeout.connect(loop.quit)
    loop.exec_()


class my_path_object(QObject):
    """
    Custom QObject subclass to emit a signal when a path is not found.
    """
    path_not_found = pyqtSignal(str)

    def __init__(self):
        super().__init__()

    def invoke(self, message):
        """
        Emits the path_not_found signal with the specified message.

        Args:
            message (str): Error message indicating the path not found.
        """
        self.path_not_found.emit(message)


class invoke_progress_bar_dir(QObject):
    """
    Custom QObject subclass to emit a signal for updating a progress bar related to directory scanning.
    """
    vt_scan_dir_signal = pyqtSignal(int)

    def __init__(self):
        super().__init__()

    def invoke(self, value):
        """
        Emits the vt_scan_dir_signal with the specified value.

        Args:
            value (int): Value indicating the progress of directory scanning.
        """
        self.vt_scan_dir_signal.emit(value)


class invoke_progress_bar_ip(QObject):
    """
    Custom QObject subclass to emit a signal for updating a progress bar related to IP scanning.
    """
    vt_scan_ip_signal = pyqtSignal(int)

    def __init__(self):
        super().__init__()

    def invoke(self, value):
        """
        Emits the vt_scan_ip_signal with the specified value.

        Args:
            value (int): Value indicating the progress of IP scanning.
        """
        self.vt_scan_ip_signal.emit(value)


def show_message_warning_box(message, on_close_func=None):
    """
    Displays a warning message box with the specified message.

    Args:
        message (str): Warning message to display.
        on_close_func (function, optional): Function to call when the message box is closed. Defaults to None.
    """
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
    """
    A custom message box dialog that displays a message with an icon and an OK button.
    """
    def __init__(self, title, message, message_type='warning', parent=None):
        """
        Initialize the MessageBox dialog.

        :param title: The title of the message box.
        :param message: The message to be displayed.
        :param message_type: The type of the message box ('warning', 'info', 'error').
        :param parent: The parent widget of the message box.
        """
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
        """
        Show the message box dialog.
        """
        self.exec_()


class StatusBar:
    """
    A custom status bar that displays messages and hides them after a certain time.
    """
    def __init__(self):
        """
        Initialize the StatusBar.
        """
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
        """
        Get the instance of the status bar.

        Returns:
            QStatusBar: The status bar instance.
        """
        return self.statusBar

    def show_message(self, message):
        """
        Show a message on the status bar for a specific duration.

        Args:
            message (str): The message to be displayed on the status bar.
        """
        self.statusBar.showMessage(message)
        self.timer = QTimer()
        self.timer.timeout.connect(self.hide_status_message)
        self.timer.start(5000)  # hide message after 5 seconds

    def hide_status_message(self):
        """
        Hide the status bar message.
        """
        self.timer.stop()
        self.statusBar.clearMessage()

    def show_few(self, messages):
        """
        Show multiple messages on the status bar with a certain interval.

        Args:
            messages (list): A list of messages to be displayed on the status bar.
        """
        self.statusBar.clearMessage()
        timer = QTimer()
        timer.setInterval(5000)  # set the interval to 5 seconds
        index = 0

        def show_message():
            """
            Display the next message in the list on the status bar.
            If all messages have been displayed, stop the timer and clear the status bar.
            """
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
    """
    A worker class for executing a function in a separate thread.

    This class is designed to be used with PyQt and provides signals for
    indicating the completion of the function execution.

    Args:
        func (function): The function to be executed in a separate thread.
        *args: Variable length argument list to be passed to the function.
        **kwargs: Arbitrary keyword arguments to be passed to the function.
    """
    finished_function = pyqtSignal()
    """
    Signal emitted when the function execution is finished.
    """

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs

    @pyqtSlot()
    def do_work(self):
        """
        Perform the actual execution of the function.

        This method is called when the worker is started in a separate thread.
        It invokes the provided function with the given arguments and emits
        the `finished_function` signal to indicate the completion of execution.
        """
        print("got to do work")
        self.func(*self.args, **self.kwargs)
        self.finished_function.emit()


def show_loading_menu(message):
    """
    Show a loading menu overlay with a GIF animation and text message.

    Args:
        message (str): The text message to be displayed in the loading menu.

    Returns:
        OverlayWindow: The instance of the loading menu overlay.

    """
    # self.clearLayout()

    class GifThread(QThread):
        """
        A QThread subclass for running the GIF animation.

        Args:
            label (QLabel): The label widget to display the GIF animation.
            movie (QMovie): The QMovie object containing the GIF animation.
        """
        def __init__(self, label, movie):
            QThread.__init__(self)
            self.label = label
            self.movie = movie

        def run(self):
            self.movie.start()

    class OverlayWindow(QMainWindow):
        """
        A QMainWindow subclass representing the loading menu overlay.

        The overlay window displays a GIF animation and a text label.

        Attributes:
            label_load (QLabel): The label widget to display the GIF animation.
            text_label (QLabel): The label widget to display the text.
            layout_load (QVBoxLayout): The main layout of the loading menu.
        """
        def __init__(self):
            super().__init__()
            self.initUI()

        def initUI(self):
            """
            Initialize the user interface of the loading menu.
            """
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
    """
    Display a loading menu with an image and text.

    Args:
        message (str): The text to be displayed in the loading menu.
        image_path (str): The path to the image file.

    Returns:
        OverlayWindow: An instance of the OverlayWindow class representing the loading menu.
    """

    class OverlayWindow(QMainWindow):
        """
        A QMainWindow subclass representing the loading menu overlay.

        The overlay window displays an image and a text label.

        Attributes:
            label_image (QLabel): The label widget to display the image.
            text_label (QLabel): The label widget to display the text.
            layout_load (QVBoxLayout): The main layout of the loading menu.
        """
        def __init__(self):
            super().__init__()
            self.initUI()

        def initUI(self):
            """
            Initialize the user interface of the loading menu.
            """
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
    """
    A custom style class for QDial controls.

    This class inherits from QProxyStyle and overrides the drawComplexControl method
    to customize the appearance of QDial controls.

    """
    def drawComplexControl(self, control, option, painter, widget=None):
        """
        Draw a complex control with customized style.

        Args:
            control (QStyle.ComplexControl): The type of the complex control to draw.
            option (QStyleOptionComplex): The style options for the control.
            painter (QPainter): The painter used to draw the control.
            widget (QWidget): The widget that the control belongs to.

        """
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
    """
    A custom widget that displays a dial with a color representing a percentage value.

    This widget provides methods to set the dial value, retrieve the current value,
    and customize the dial color based on the value.

    """
    def __init__(self):
        """
        Initialize the DialWatch widget.

        """
        super().__init__()
        self.initUI()

    def initUI(self):
        """
        Set up the user interface of the DialWatch widget.

        """
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
        """
        Get the QDial object used in the DialWatch widget.

        Returns:
            QDial: The QDial object.

        """

        return self.dial

    def onDialChanged(self, value):
        """
        Handle the dial value change event.

        Args:
            value (int): The new value of the dial.

        """
        percentage = value + 1
        self.setDialColor(percentage)

    def setDialPercentage(self, percentage):
        """
        Set the dial value based on a percentage.

        Args:
            percentage (int): The desired percentage value.

        """
        if percentage >= 99:
            percentage = 99
        self.dial.setValue(percentage - 1)
        self.setDialColor(percentage)

    def get_percentage(self):
        """
        Get the current percentage value of the dial.

        Returns:
            int: The current percentage value.

        """
        return self.dial.value() + 1

    def setDialColor(self, percentage):
        """
        Set the color of the dial based on a percentage value.

        Args:
            percentage (int): The percentage value.

        """
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
    """
    A class that represents an event viewer with a table widget to display event information.

    The event viewer can read event data from a file and populate the table with the event details.

    """
    def __init__(self):
        """
        Initialize the EventViewer.

        """
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
        """
        Populate the table widget with event data.

        """
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
        """
        Add an event to the table widget.

        Args:
            number (str): The event number.
            type (str): The type of event.
            perm (str): The event permissions.
            resource (str): The event resources.
            color (str or QColor): The color of the event.

        """

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
    """
    Write data to a text file excluding a specific line.

    Args:
        path (str): The path to the file.
        line (str): The line to exclude from the file.
        original_data (str): The original data to write to the file.

    """
    with open(path, "w") as f:
        for line_file in original_data.split("\n"):
            if line.strip() == line_file.strip():
                continue
            f.write(line_file)


class OverLayQuarantined(QMainWindow):
    """
    A class that represents a quarantined file overlay window.

    The overlay window displays a table of quarantined files and allows the user to select a file for restoration.

    """
    closed = pyqtSignal()

    def __init__(self):
        """
        Initialize the OverlayQuarantined window.

        """

        super().__init__()
        self.initUI()

    def initUI(self):
        """
        Initialize the user interface of the overlay window.

        """
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
            """
            Close the overlay window.

            Emits the `closed` signal and closes the window.

            """
            self.closed.emit()
            self.close()

        close_button.clicked.connect(lambda: close())

        self.name_to_quarantine = None
        self.date_to_quarantine = None

    def mousePressEvent(self, event):
        """
        Handle the mouse press event.

        Stores the position of the mouse press event.

        Args:
            event (QMouseEvent): The mouse press event.

        """
        self.offset = event.pos()

    def add_data(self):
        """
        Add data to the table.

        Reads data from the "quarantine_data.txt" file and populates the table with the data.

        """
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
        """
        Handle the mouse move event.

        Moves the overlay window based on the mouse movement.

        Args:
            event (QMouseEvent): The mouse move event.

        """
        x = event.globalX()
        y = event.globalY()
        x_w = self.offset.x()
        y_w = self.offset.y()
        self.move(x - x_w, y - y_w)

    def keyPressEvent(self, event):
        """
        Handle the key press event.

        Closes the overlay window if the Escape key is pressed.

        Args:
            event (QKeyEvent): The key press event.

        """
        if event.key() == Qt.Key_Escape:
            self.close()

    def createTitleLabel(self, text):
        """
        Create a title label widget.

        Creates a QLabel widget with a decorative font, purple text color, and a shadow effect.

        Args:
            text (str): The text to display on the label.

        Returns:
            QLabel: The created title label widget.

        """
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
        """
        Get the index of a line in a file.

        Searches for a specific line in the file and returns its index.

        Args:
            filename (str): The path to the file.
            search_line (str): The line to search for.

        Returns:
            int: The index of the matching line, or None if the line is not found.

        """
        with open(filename, 'r') as f:
            for i, line in enumerate(f):
                if line.strip() == search_line.strip():
                    return i  # return the index of the matching line
        return None  # return None if the specified line is not found in the file

    def handleSelection(self):
        """
        Handle the selection event of the table.

        Retrieves the selected row from the table, extracts relevant data, and performs necessary operations.

        If a row is selected, it retrieves the name and date from the selected row.
        It then searches for a matching line in the "quarantine_data.txt" file and extracts the hash and original file path.
        If the original file exists in the quarantine folder, it restores it to the original location using the Quarantine class.
        It then removes the matching line from the "quarantine_data.txt" file.
        Finally, it emits the `closed` signal and closes the overlay window.

        """
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
