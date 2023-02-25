import sys
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *


class DialWatch(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # Create a vertical layout for the dial watch
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Create a label for the dial watch
        label = QLabel("Dial Watch")
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)

        # Create a dial widget
        self.dial = QDial()
        self.dial.setRange(0, 99)
        self.dial.setFixedSize(100, 100)
        self.dial.setStyleSheet("background-color: red; border-radius: 25px")
        self.dial.setNotchesVisible(True)
        self.dial.notchSize = 20
        self.dial.valueChanged.connect(self.onDialChanged)
        layout.addWidget(self.dial)

        # Set the window properties
        self.setWindowTitle("Dial Watch")
        self.setGeometry(100, 100, 200, 150)
        self.show()

    def onDialChanged(self, value):
        print(f"Current value: {value+1}%")

    def setDialPercentage(self, percentage):
        self.dial.setValue(percentage-1)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    dial_watch = DialWatch()
    dial_watch.setDialPercentage(5) # set the dial to 25%
    sys.exit(app.exec_())
