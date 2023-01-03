import sys
from PyQt5.QtWidgets import QApplication, QLabel, QMainWindow, QPushButton, QVBoxLayout, QWidget


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.label1 = QLabel("Label 1")
        self.label2 = QLabel("Label 2")
        self.button = QPushButton("Button")

        layout = QVBoxLayout()
        layout.addWidget(self.label1)
        layout.addWidget(self.button)

        # Insert label2 before the button
        layout.insertWidget(1, self.label2)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

app = QApplication(sys.argv)
window = MainWindow()
window.show()
sys.exit(app.exec_())