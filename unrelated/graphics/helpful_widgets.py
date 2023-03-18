import os
import sys
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

class StatusBar:

    def __init__(self):
        self.statusBar = QStatusBar()
        self.statusBar.setStyleSheet("""
                    QStatusBar {
                        border-top: 1px solid #444;
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
        self.statusBar.clearMessage()

def show_loading_menu():
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
            self.text_label = QLabel("Loading your data...")
            self.label_load.setAlignment(Qt.AlignCenter)

            # Style the text label
            font = QFont()
            font.setFamily("Zapfino")
            font.setPointSize(20)
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


class DialWatch(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # Create a dial widget
        self.dial = QDial()
        self.dial.setRange(0, 99)
        self.dial.setFixedSize(100, 100)
        self.dial.setStyleSheet("border-radius: 25px; margin-left: 20px;")
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
                            for resource in data[3:]:
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


if __name__ == '__main__':
    app = QApplication(sys.argv)
    dial_watch = DialWatch()
    dial_watch.setDialPercentage(5)  # set the dial to 25%
    sys.exit(app.exec_())
