from PyQt5.QtWidgets import QListWidget, QListWidgetItem, QApplication, QWidget, QHBoxLayout, QLabel
from PyQt5.QtGui import QColor, QPainter
import sys


class CustomListWidgetItem(QListWidgetItem):
    def __init__(self, text, color, parent=None):
        super().__init__(parent)

        self.text = text
        self.color = color

        layout = QHBoxLayout()
        layout.addWidget(QLabel(text))
        self.setLayout(layout)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setPen(QColor(self.color))
        painter.drawText(event.rect(), self.text)


app = QApplication(sys.argv)
list_widget = QListWidget()

item1 = CustomListWidgetItem("Item 1", "red")
item2 = CustomListWidgetItem("Item 2", "black")
item3 = CustomListWidgetItem("Item 3", "red")

list_widget.addItem(item1)
list_widget.addItem(item2)
list_widget.addItem(item3)

list_widget.show()
sys.exit(app.exec_())
