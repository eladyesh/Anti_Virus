import sys
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication, QWidget, QLabel


class MyWindow(QWidget):
    def __init__(self):
        super().__init__()

        # Create a label widget to add to the top-right corner
        self.label = QLabel("Hello World!", self)

        # Set the background color of the widget
        self.setStyleSheet("background-color: white;")

        # Set the initial position of the label widget
        self.update_label_position()

        # Connect the resizeEvent to the update_label_position method
        self.resizeEvent = self.update_label_position

    def update_label_position(self, event=None):
        # Calculate the new position of the label widget based on the size of the window
        label_width = self.label.sizeHint().width()
        window_width = self.width()
        x = window_width - label_width
        self.label.move(x - 20, 20)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MyWindow()
    window.setGeometry(100, 100, 400, 300)
    window.show()
    sys.exit(app.exec_())
