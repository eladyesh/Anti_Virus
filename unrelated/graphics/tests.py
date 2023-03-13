import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget
from qtwidgets import Toggle, AnimatedToggle


class Example(QMainWindow):
    def __init__(self):
        super().__init__()

        # Create a layout for the widgets
        layout = QVBoxLayout()

        # Add a Toggle widget to the layout
        self.toggle = Toggle()
        layout.addWidget(self.toggle)

        # Add an AnimatedToggle widget to the layout
        self.animated_toggle = AnimatedToggle(checked_color="green", pulse_checked_color="red")
        layout.addWidget(self.animated_toggle)

        # Add an "Apply" button to the layout
        self.apply_button = QPushButton("Apply")
        self.apply_button.setStyleSheet("""
            QPushButton {
                background-color: #E7E7FA;
                color: #000080;
                border: 2px solid #9400D3;
                font: bold 25px;
                min-width: 80px;
                margin: 5px;
                margin-bottom: 10px;
                padding: 10px;
            }

            QPushButton:hover {
                background-color: #D8BFD8;
                color: #4B0082;
            }

            QPushButton:pressed {
                background-color: #DDA0DD;
                color: #8B008B;
            }
        """)
        self.apply_button.clicked.connect(self.check_toggle)
        layout.addWidget(self.apply_button)

        # Create a central widget and set the layout
        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def check_toggle(self):
        if self.toggle.isChecked():
            print("Toggle is checked!")
        else:
            print("Toggle is not checked!")

        if self.animated_toggle.isChecked():
            print("Animated toggle is checked!")
        else:
            print("Animated toggle is not checked!")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = Example()
    ex.show()
    sys.exit(app.exec_())
