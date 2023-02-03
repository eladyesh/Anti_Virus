import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QGridLayout, QWidget


class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # Create the central widget and layout
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        grid_layout = QGridLayout(central_widget)

        # Create the buttons and add them to the layout
        for i in range(1, 20):
            button = QPushButton(str(i), self)
            grid_layout.addWidget(button, (i - 1) // 5, (i - 1) % 5)

        self.show()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MyApp()
    window.show()
    sys.exit(app.exec_())