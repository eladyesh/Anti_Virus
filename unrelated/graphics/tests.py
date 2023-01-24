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

root = QStandardItem()
root.appendRow(kernel32)
root.appendRow(adapi32)

tree_view.setStyleSheet("""
QTreeView {
    background-color: #3b2e3e;
    color: white;
    border: 1px solid #ccc;
    font-family: "Arial";
    font-size: 12px;
}

QTreeView::item {
    padding: 5px;
    border-bottom: 1px solid #ccc;
}

QTreeView::item:hover {
    background-color: #6a4d6f;
}

QTreeView::item:selected {
    background-color: #907aa8;
    color: #f4f4f4;
}
""")

model = QStandardItemModel()
model.appendRow(root)
tree_view.setModel(model)
tree_view.show()
app.exec_()
