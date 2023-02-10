import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QProgressBar
import time

class ProgressBarWindow(QMainWindow):
    def _init_(self):
        super()._init_()

        self.progress = QProgressBar(self)
        self.progress.setGeometry(30, 40, 200, 25)

        self.setCentralWidget(self.progress)

    def scanDirectory(self, path):
        files = os.listdir(path)
        num_files = len(files)
        for i, file in enumerate(files):
            time.sleep()
            self.progress.setValue((i+1)/num_files * 100)

app = QApplication(sys.argv)
window = ProgressBarWindow()
window.show()
window.scanDirectory("")
sys.exit(app.exec_())