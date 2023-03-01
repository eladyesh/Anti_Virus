import os
import sys
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *


class DialWatch(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):

        # Create a dial widget
        self.dial = QDial()
        self.dial.setRange(0, 99)
        self.dial.setFixedSize(100, 100)
        self.dial.setStyleSheet("background-color: red; border-radius: 25px")
        self.dial.setNotchesVisible(True)
        self.dial.notchSize = 20
        self.dial.valueChanged.connect(self.onDialChanged)

    def onDialChanged(self, value):
        print(f"Current value: {value + 1}%")

    def setDialPercentage(self, percentage):
        self.dial.setValue(percentage - 1)


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
