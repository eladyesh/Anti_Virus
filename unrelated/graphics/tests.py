import os
import shutil
import subprocess
import ppdeep

# source_path = r"D:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\pe_scan\malicious_exe's\c#_virus.exe"
#
# shutil.copy(source_path, os.getcwd() + "/virus.exe")

# print(ppdeep.hash_from_file(r"D:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\python_exe\test.py"))
import sys
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QMessageBox


class DrivingTestPass(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setGeometry(300, 300, 300, 200)
        self.setWindowTitle('Driving Test Pass')

        btn = QPushButton('Pass Your Driving Test', self)
        btn.setToolTip('Click to pass your driving test')
        btn.move(50, 50)
        btn.clicked.connect(self.showMsg)

        self.show()

    def showMsg(self):
        msg = QMessageBox()
        msg.setWindowTitle('Driving Test Pass')
        msg.setText('The next driving test you take will be successful')
        msg.setIcon(QMessageBox.Information)
        msg.exec_()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = DrivingTestPass()
    sys.exit(app.exec_())
