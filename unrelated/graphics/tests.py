from PyQt5.QtWidgets import QApplication, QMainWindow, QStatusBar
from PyQt5.QtCore import QTimer


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.statusBar = QStatusBar()
        self.statusBar.setStyleSheet("""
    QStatusBar {
        border-top: 1px solid #ddd;
        background-color: #F5F5F5;
    }
    
    QStatusBar::item {
        border: none;
    }
    
    QStatusBar QLabel {
        color: #555;
        font-size: 14px;
        font-weight: bold;
        padding-left: 10px;
    }
    
    QStatusBar QLabel#statusMessage {
        color: #28a745;
    }
""")
        self.setStatusBar(self.statusBar)
        self.show_status_message("Your file is ready")
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.hide_status_message)
        self.timer.start(3000)  # hide message after 3 seconds

    def show_status_message(self, message):
        self.statusBar.showMessage(message)

    def hide_status_message(self):
        self.statusBar.clearMessage()


if __name__ == "__main__":
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec_()