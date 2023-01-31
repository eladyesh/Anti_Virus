import sys
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon, QMovie
from PyQt5.QtWidgets import QApplication, QMainWindow, QToolBar, QAction, QLabel

app = QApplication(sys.argv)

window = QMainWindow()
window.setWindowTitle("My Toolbar")

# Add a loading bar to the window
# loading_bar = QLabel(window)
# movie = QMovie("loading-circle-loading.gif")
# loading_bar.setMovie(movie)
# movie.start()
# loading_bar.setGeometry(0, 0, window.width(), 50)

toolbar = QToolBar()
toolbar.setMovable(False)

# Add actions to the toolbar
new_action = QAction(QIcon("images/arrow"), "New")
open_action = QAction(QIcon("images/arrow"), "Open")
save_action = QAction(QIcon("images/arrow"), "Save")
save_as_action = QAction(QIcon("images/arrow"), "Save As")

toolbar.addAction(new_action)
toolbar.addAction(open_action)
toolbar.addAction(save_action)
toolbar.addAction(save_as_action)

with open("css_files/toolbar.css") as f:
    toolbar.setStyleSheet(f.read())

window.addToolBar(Qt.LeftToolBarArea, toolbar)
window.show()

sys.exit(app.exec_())
