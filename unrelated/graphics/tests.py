import sys
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QMainWindow, QToolBar, QAction, QTextEdit

app = QApplication(sys.argv)

window = QMainWindow()
window.setWindowTitle("My Toolbar")

toolbar = QToolBar()
toolbar.setMovable(False)
toolbar.setStyleSheet("""
QToolBar {
background-color: #303030;
color: white;
padding: 10px;
border: 1px solid #9b59b6;
}

QToolBar QAction {
background-color: #303030;
color: white;
}

QToolBar QAction:hover {
background-color: #9b59b6;
color: white;
}
""")

# Add actions to the toolbar
new_action = QAction(QIcon("images/arrow"), "")
open_action = QAction(QIcon("images/arrow"), "")
save_action = QAction(QIcon("images/arrow"), "")
save_as_action = QAction(QIcon("images/arrow"), "")

toolbar.addAction(new_action)
toolbar.addAction(open_action)
toolbar.addAction(save_action)
toolbar.addAction(save_as_action)

window.addToolBar(Qt.LeftToolBarArea, toolbar)
window.show()

sys.exit(app.exec_())