import os

import PyQt5
from PyQt5 import QtWidgets
from qtwidgets import Toggle, AnimatedToggle


class Window(QtWidgets.QMainWindow):

    def __init__(self):
        super().__init__()

        toggle_1 = Toggle()
        toggle_2 = AnimatedToggle(
            checked_color="#FFB000",
            pulse_checked_color="#44FFB000"
        )

        hbox_1 = QtWidgets.QHBoxLayout()
        label_1 = QtWidgets.QLabel("Toggle 1")
        hbox_1.addWidget(label_1)
        hbox_1.addWidget(toggle_1)

        hbox_2 = QtWidgets.QHBoxLayout()
        label_2 = QtWidgets.QLabel("Toggle 2")
        hbox_2.addWidget(label_2)
        hbox_2.addWidget(toggle_2)

        container = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()
        layout.addLayout(hbox_1)
        layout.addLayout(hbox_2)
        container.setLayout(layout)

        self.setCentralWidget(container)


app = QtWidgets.QApplication([])
w = Window()
w.show()
print(os.getcwd())
app.exec_()
