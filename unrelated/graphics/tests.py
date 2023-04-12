from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QAbstractScrollArea

class Example(QMainWindow):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle('Example')
        self.setGeometry(100, 100, 400, 300)

        # Create a QTableWidget
        self.tableWidget = QTableWidget(self)
        self.tableWidget.setRowCount(4)
        self.tableWidget.setColumnCount(3)
        self.tableWidget.setHorizontalHeaderLabels(['Column 1', 'Column 2', 'Column 3'])
        self.tableWidget.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents) # Set sizeAdjustPolicy

        # Add some data to the table
        for row in range(self.tableWidget.rowCount()):
            for column in range(self.tableWidget.columnCount()):
                self.tableWidget.setItem(row, column, QTableWidgetItem(f'({row}, {column})'))

        # Set the maximum size of the table to its current sizeHint
        self.tableWidget.setMaximumSize(self.tableWidget.sizeHint())

        # Set the central widget of the QMainWindow
        self.setCentralWidget(self.tableWidget)

    def resizeEvent(self, event):
        self.tableWidget.resizeColumnsToContents() # Resize the columns to fit their contents
        constant = 1.5 # Set the constant
        new_size = self.tableWidget.sizeHint() * constant # Multiply the sizeHint by the constant
        self.resize(new_size) # Resize the window to fit the table

if __name__ == '__main__':
    app = QApplication([])
    ex = Example()
    ex.show()
    app.exec_()
