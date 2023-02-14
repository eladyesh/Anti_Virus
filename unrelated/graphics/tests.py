from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem


class LogWindow(QMainWindow):
    def __init__(self, log):
        super().__init__()

        # Create the table widget
        self.table = QTableWidget(len(log), 4)
        self.table.setHorizontalHeaderLabels(['Variable name', 'Library name', 'Function name', 'Parameters'])
        self.setCentralWidget(self.table)

        # Populate the table with the log information
        for i, chunk in enumerate(log):
            fields = chunk.split("\n")
            for j, field in enumerate(fields):
                item = QTableWidgetItem(field)
                self.table.setItem(i, j, item)


if __name__ == '__main__':
    # Example usage
    log = [
        "Variable name: value\nLibrary name: winsock\nFunction name: socket\nParameters: 2, 1, 6",
        "Library name: winsock\nFunction name: getaddrinfo\nParameters: target, None, None, ctypes.byref(address)",
        "Variable name: result\nLibrary name: winsock\nFunction name: connect\nParameters: s, address, ctypes.sizeof(address), port"
    ]

    app = QApplication([])
    window = LogWindow(log)
    window.show()
    app.exec_()
