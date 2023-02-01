import sys
from PyQt5 import QtWidgets, QtGui, QtCore

class OverlayWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.WindowStaysOnTopHint)
        self.setGeometry(100, 100, 200, 100)

        # Create the label for the text
        label = QtWidgets.QLabel("Loading your data...")
        label.setAlignment(QtCore.Qt.AlignCenter)

        # Style the text label
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(20)
        font.setBold(True)
        label.setFont(font)
        label.setStyleSheet("color: blue;")

        # Create the main layout
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(label, 0, QtCore.Qt.AlignCenter)

        central_widget = QtWidgets.QWidget(self)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        close_button = QtWidgets.QPushButton('X', self)
        close_button.setFixedSize(30, 30)
        close_button.clicked.connect(self.close)
        close_button.move(170, 0)

    def mousePressEvent(self, event):
        self.offset = event.pos()

    def mouseMoveEvent(self, event):
        x = event.globalX()
        y = event.globalY()
        x_w = self.offset.x()
        y_w = self.offset.y()
        self.move(x-x_w, y-y_w)

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        button = QtWidgets.QPushButton("Open Overlay", self)
        button.clicked.connect(self.openOverlay)
        button.move(50, 50)

    def openOverlay(self):
        self.overlay_window = OverlayWindow()
        self.overlay_window.show()

app = QtWidgets.QApplication(sys.argv)
main_window = MainWindow()
main_window.show()
sys.exit(app.exec_())
