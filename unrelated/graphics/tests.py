from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QErrorMessage


class MyApp(QWidget):
    def __init__(self):
        super().__init__()

        # Create a button to trigger an error
        self.button = QPushButton("Trigger Error")
        self.button.clicked.connect(self.trigger_error)

        # Create a layout and add the button to it
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.button)

        # Set the layout for the main window
        self.setLayout(self.layout)

    def trigger_error(self):
        # Create an error message object
        error_message = QErrorMessage(self)

        # Set the error message text
        error_message.setWindowTitle("Error")
        error_message.showMessage("An error has occurred.")

if __name__ == '__main__':
    app = QApplication([])
    window = MyApp()
    window.show()
    app.exec_()
