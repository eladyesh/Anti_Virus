import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel
from PyQt5.QtGui import QFont


class ErrorWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        error_label = QLabel("This is an error message!", self)
        error_label.setFont(QFont("DemiBold", 30))
        error_label.setStyleSheet("color: red;")

        self.setGeometry(300, 300, 400, 200)
        self.setWindowTitle('Error Message')
        self.show()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = ErrorWindow()
    sys.exit(app.exec_())
