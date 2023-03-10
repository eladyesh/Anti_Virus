from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QTextCursor
from PyQt5.QtWidgets import QApplication, QWidget, QTextEdit, QVBoxLayout, QPushButton
import sys

class AlertWidget(QWidget):
    def __init__(self, message, alert_type="info"):
        super().__init__()

        # set the background and text color based on the alert type
        if alert_type == "warning":
            bg_color = QColor(255, 255, 153) # yellow
            text_color = QColor(0, 0, 0) # black
        elif alert_type == "error":
            bg_color = QColor(255, 102, 102) # red
            text_color = QColor(255, 255, 255) # white
        else:
            bg_color = QColor(204, 255, 204) # green
            text_color = QColor(0, 0, 0) # black

        # create a QTextEdit widget to display the alert message
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setPlainText(message)
        self.text_edit.setStyleSheet("background-color: {}; color: {};".format(bg_color.name(), text_color.name()))

        # create a button to dismiss the widget
        self.button = QPushButton("OK")
        self.button.clicked.connect(self.close)

        # add the QTextEdit and QPushButton widgets to a vertical layout
        layout = QVBoxLayout()
        layout.addWidget(self.text_edit)
        layout.addWidget(self.button)

        self.setLayout(layout)

        # set the widget to be shown in the center of the screen
        self.setGeometry(
            QApplication.desktop().screenGeometry().width() / 2 - 200,
            QApplication.desktop().screenGeometry().height() / 2 - 100,
            400,
            200
        )

        self.show()

if __name__ == "__main__":
    app = QApplication(sys.argv)

    # create an instance of the custom alert widget
    widget = AlertWidget("This is an info message.")

    # set the alert type to "warning"
    # widget = AlertWidget("This is a warning message.", "warning")

    # set the alert type to "error"
    # widget = AlertWidget("This is an error message.", "error")

    # enter the event loop
    sys.exit(app.exec_())
