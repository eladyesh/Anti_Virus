from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

qss = """
#Window{ 
    background-color: white 
}
QPushButton[flat="true"]{
    background-color: black;
    border: 0px;
}
"""


class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        toolbar = self.addToolBar("toolbar")
        self.button1 = QPushButton(self, flat=True)
        self.button1.setText("hello")
        toolbar.addWidget(self.button1)


if __name__ == '__main__':
    import sys

    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())
