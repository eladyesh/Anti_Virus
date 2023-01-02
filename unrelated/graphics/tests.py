import sys
from PyQt5.QtWidgets import QApplication, QTableView, QHeaderView
from PyQt5.QtCore import Qt, QAbstractTableModel, QVariant


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


# Create the QApplication
app = QApplication(sys.argv)

# Create the QTableView
table_view = QTableView()

# Set the model on the QTableView
data = [
    ['Item 1', 'Value 1'],
    ['Item 2', 'Value 2'],
]
model = TableModel(data)
table_view.setModel(model)

# Set the style sheet and disable editing
style_sheet = """
QTableView {
    font-family: "Arial Black";
    font-size: 20pt;
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

table_view.setStyleSheet(style_sheet)
table_view.setEditTriggers(QTableView.NoEditTriggers)

# Allow the cells to be resized using the mouse
table_view.horizontalHeader().setSectionsMovable(True)
table_view.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)

# Show the table view
table_view.show()

# Run the application loop
sys.exit(app.exec_())
