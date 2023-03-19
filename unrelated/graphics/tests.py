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

        # Create a worker thread to monitor the file
        self.worker = Worker()
        self.worker.file_changed.connect(self.on_file_changed)
        self.worker.start()

    def on_file_changed(self):
        self.statusBar().showMessage('Ready')

class Worker(QObject, threading.Thread):
    file_changed = pyqtSignal()

    def __init__(self):
        super().__init__()

    def run(self):

        # Monitor the file
        while not os.path.exists('log.txt'):
            time.sleep(1)

        # File found, emit signal
        self.file_changed.emit()

if __name__ == '__main__':
    # Create and run the application
    app = QApplication(sys.argv)
    demo = AppDemo()
    demo.show()

    # Wait 5 seconds and create the empty file
    time.sleep(5)
    with open('log.txt', 'w') as f:
        f.write('This is a test')

    sys.exit(app.exec_())
