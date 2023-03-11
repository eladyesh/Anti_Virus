import sys
from PyQt5.QtWidgets import QApplication, QWidget, QListWidget, QVBoxLayout, QHBoxLayout, QLabel

app = QApplication(sys.argv)
window = QWidget()
layout = QVBoxLayout()

# Create the first row of QListWidgets
row1_layout = QHBoxLayout()
for i in range(3):
    list_widget = QListWidget()
    list_widget.addItem("Item 1")
    list_widget.addItem("Item 2")
    label = QLabel("Hello")
    row1_layout.addWidget(label)
    row1_layout.addWidget(list_widget)

# Create the second row of QListWidgets
row2_layout = QHBoxLayout()
for i in range(2):
    list_widget = QListWidget()
    list_widget.addItem("Item 1")
    list_widget.addItem("Item 2")
    label = QLabel("Hello")
    row2_layout.addWidget(label)
    row2_layout.addWidget(list_widget)

# Add the two rows of QListWidgets to the main layout
layout.addLayout(row1_layout)
layout.addLayout(row2_layout)

window.setLayout(layout)
window.show()
sys.exit(app.exec_())