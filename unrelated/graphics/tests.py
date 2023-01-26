# import sys
# from PyQt5.QtCore import Qt, QPointF, QRectF
# from PyQt5.QtGui import QPalette, QColor, QPen, QPainterPath, QPainter, QFont
# from PyQt5.QtWidgets import QApplication, QListWidget, QLabel, QStyledItemDelegate, QVBoxLayout, QWidget, QStyle, \
#     QListWidgetItem, QMainWindow, QGraphicsDropShadowEffect
#
#
# class bubbleWidget(QWidget):
#     def __init__(self, text, parent=None):
#         super().__init__(parent)
#         self.text = text
#         self.setWindowFlags(Qt.ToolTip)
#         self.setAttribute(Qt.WA_TranslucentBackground)
#
#     def paintEvent(self, event):
#         path = QPainterPath()
#         path.addRoundedRect(QRectF(self.rect().adjusted(10, 10, -10, -10)), 10, 10)
#         painter = QPainter(self)
#         painter.setBrush(QColor("white"))
#         painter.setPen(Qt.NoPen)
#         painter.drawPath(path)
#         painter.setPen(QPen(Qt.black))
#         font = QFont("Arial", 12, QFont.Bold)
#         painter.setFont(font)
#         painter.drawText(path.boundingRect(), Qt.AlignCenter, self.text)
#
#
# class MainWindow(QMainWindow):
#     def __init__(self, parent=None):
#         super().__init__(parent)
#         self.list_widget = QListWidget()
#         self.setCentralWidget(self.list_widget)
#         for i in range(5):
#             item = QListWidgetItem("Item " + str(i))
#             self.list_widget.addItem(item)
#             self.list_widget.setItemWidget(item, QLabel("Name: Item " + str(i)))
#             self.list_widget.setMouseTracking(True)
#             self.list_widget.itemEntered.connect(self.show_bubble)
#             self.bubble = bubbleWidget(item.text())
#             self.bubble.hide()
#
#     def show_bubble(self, item):
#         item_text = item.text()
#         self.bubble = bubbleWidget(item_text)
#         pos = self.list_widget.visualItemRect(item).topRight()
#         pos.setX(pos.x() + 20)
#         self.bubble.move(self.list_widget.mapToGlobal(pos))
#         self.bubble.show()
#
#     def leaveEvent(self, event):
#         self.bubble.hide()
#
#
# if __name__ == "__main__":
#     app = QApplication(sys.argv)
#     window = MainWindow()
#     window.show()
#     sys.exit(app.exec_())
