import sys
from PyQt5 import QtWidgets, QtGui

app = QtWidgets.QApplication(sys.argv)

progress = QtWidgets.QProgressBar()
progress.setRange(0, 100)
progress.setValue(50)

palette = progress.palette()
palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(124,252,0))
progress.setPalette(palette)

progress.show()

sys.exit(app.exec_())