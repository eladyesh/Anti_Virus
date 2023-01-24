from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QTreeView, QApplication
app = QApplication([])
tree_view = QTreeView()

kernel32 = QStandardItem("Kernel32.dll")
createFileA = QStandardItem("CreateFileA")
sleep = QStandardItem("Sleep")
kernel32.appendRow(createFileA)
kernel32.appendRow(sleep)

adapi32 = QStandardItem("Adapi32.dll")
regCreateKeyExA = QStandardItem("RegCreateKeyExA")
adapi32.appendRow(regCreateKeyExA)
adapi32.appendRow(QStandardItem("RegCreateKeyExA"))

root = QStandardItem("Imports")
root.appendRow(kernel32)
root.appendRow(adapi32)

tree_view.setStyleSheet("""
QTreeView {
    background-color: white;
    color: #907aa8;
    border: 1px solid #3b2e3e;
    font-family: "Verdana";
    font-size: 14px;
}

QTreeView::item {
    padding: 5px;
    border-bottom: 1px solid #3b2e3e;
}

QTreeView::item:hover {
    background-color: #d6c7e3;
    box-shadow: 2px 2px 5px #907aa8;
}

QTreeView::item:selected {
    background-color: #907aa8;
    color: black;
    border-bottom: 2px solid black;
}
""")

model = QStandardItemModel()
model.appendRow(root)
tree_view.setModel(model)
tree_view.show()
app.exec_()
