import sys

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication, QListWidget, QWidget, QVBoxLayout, QScrollBar

app = QApplication(sys.argv)
window = QWidget()

# Create a list widget and add some items to it
listWidget = QListWidget()
for i in range(1, 101):
    listWidget.addItem(str(i))

# Create a scroll bar and set its properties
scrollBar = QScrollBar()
scrollBar.setOrientation(Qt.Vertical)
scrollBar.setMinimum(0)
scrollBar.setMaximum(100)
scrollBar.setSingleStep(1)
scrollBar.setPageStep(10)
scrollBar.setValue(50)

# Customize the appearance of the scroll bar
scrollBar.setStyleSheet("""
    QScrollBar:vertical {
        border: none;
        background: #eee;
        width: 15px;
        margin: 0px 0px 0px 0px;
    }

    QScrollBar::handle:vertical {
        background: #ccc;
        min-height: 20px;
        border-radius: 5px;
    }

    QScrollBar::add-line:vertical {
        background: none;
        height: 0px;
        subcontrol-position: bottom;
        subcontrol-origin: margin;
    }

    QScrollBar::sub-line:vertical {
        background: none;
        height: 0px;
        subcontrol-position: top;
        subcontrol-origin: margin;
    }

    QScrollBar::up-arrow:vertical, QScrollBar::down-arrow:vertical {
        border: none;
        width: 0px;
        height: 0px;
        background: none;
    }

    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
        background: none;
    }
""")


listWidget.setStyleSheet("""
    QListWidget {
        background-color: #f5f5f5;
        border: 1px solid #ccc;
        border-radius: 5px;
        outline: none;
    }

    QListWidget::item {
        color: #444;
        border: none;
        padding: 10px;
        font-size: 14px;
        font-weight: 500;
    }

    QListWidget::item:hover {
        background-color: #eee;
    }

    QListWidget::item:selected {
        background-color: #333;
        color: #fff;
    }
""")


# Create a vertical layout and add the list widget and scroll bar to it
layout = QVBoxLayout()
layout.addWidget(listWidget)
layout.addWidget(scrollBar)
listWidget.setVerticalScrollBar(scrollBar)

# Set the layout for the main window and show it
window.setLayout(layout)
window.show()

sys.exit(app.exec_())