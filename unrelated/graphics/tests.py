import sys
from PyQt5.QtCore import Qt, QPointF
from PyQt5.QtGui import QPalette, QColor, QPen, QPainterPath, QPainter
from PyQt5.QtWidgets import QApplication, QListWidget, QLabel, QStyledItemDelegate, QVBoxLayout, QWidget, QStyle, \
    QListWidgetItem, QMainWindow


class BubbleWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.ToolTip)
        self.setAttribute(Qt.WA_TranslucentBackground)

    def paintEvent(self, event):
        path = QPainterPath()
        path.moveTo(self.rect().topRight() + QPointF(20, 0))
        path.lineTo(self.rect().topRight() + QPointF(40, 20))
        path.lineTo(self.rect().topRight() + QPointF(40, 0))
        path.cubicTo(self.rect().topRight() + QPointF(40, 0), self.rect().topRight() + QPointF(40, -20),
                     self.rect().topRight() + QPointF(20, -20))
        path.closeSubpath()
        painter = QPainter(self)
        painter.setBrush(QColor("#2E2E2E"))
        painter.setPen(QPen(Qt.white, 2))
        painter.drawPath(path)
        painter.drawText(path.boundingRect(), Qt.AlignCenter, "Top Level")


class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.list_widget = QListWidget()
        self.setCentralWidget(self.list_widget)
        for i in range(5):
            item = QListWidgetItem("Item " + str(i))
            self.list_widget.addItem(item)
            self.list_widget.setItemWidget(item, QLabel("Name: Item " + str(i)))
            self.list_widget.setMouseTracking(True)
            self.list_widget.itemEntered.connect(self.show_bubble)
            self.bubble = BubbleWidget()
            self.bubble.hide()

    def show_bubble(self, item):
        pos = self.list_widget.visualItemRect(item).topRight()
        pos.setX(pos.x() + 20)
        self.bubble.move(self.list_widget.mapToGlobal(pos))
        self.bubble.show()

    def leaveEvent(self, event):
        self.bubble.hide()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())