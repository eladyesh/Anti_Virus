import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem


class EventViewer(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Event Viewer")
        self.setGeometry(100, 100, 800, 600)

        # Create table widget
        self.table = QTableWidget(self)
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Date", "Event", "Source"])
        self.table.resize(780, 580)
        self.table.move(10, 10)

        # Add some sample data to the table
        self.add_event("2022-02-27 10:30:00", "Application started", "Event Viewer")
        self.add_event("2022-02-27 11:15:00", "Application stopped", "Event Viewer")
        self.add_event("2022-02-28 08:00:00", "System rebooted", "System")

    def add_event(self, date, event, source):
        # Add a new row to the table
        row_position = self.table.rowCount()
        self.table.insertRow(row_position)

        # Add the data to the table cells
        date_item = QTableWidgetItem(date)
        self.table.setItem(row_position, 0, date_item)

        event_item = QTableWidgetItem(event)
        self.table.setItem(row_position, 1, event_item)

        source_item = QTableWidgetItem(source)
        self.table.setItem(row_position, 2, source_item)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EventViewer()
    window.show()
    sys.exit(app.exec_())
