import sys
import threading
import os
import time
from PyQt5.QtCore import QObject, pyqtSignal, Qt
from PyQt5.QtWidgets import QApplication, QMainWindow

class AppDemo(QMainWindow):
    def __init__(self):
        super().__init__()

        self.statusBar().showMessage('Not ready')
        self.setWindowTitle('Demo Application')
        self.resize(400, 300)

if __name__ == '__main__':
    # Create and run the application
    app = QApplication(sys.argv)
    demo = AppDemo()
    demo.show()

    def wait():

        # Wait 5 seconds and create the empty file
        time.sleep(5)
        with open('log.txt', 'w') as f:
            f.write('This is a test')

    t = threading.Thread(target=wait, args=())
    t.start()

    sys.exit(app.exec_())