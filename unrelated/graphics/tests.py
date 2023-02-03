import sys
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QMovie
from PyQt5.QtWidgets import QApplication, QListWidget, QLabel, QVBoxLayout, QWidget


class ListBoxWidget(QListWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        # perform drag and drop
        self.setAcceptDrops(True)
        self.setGeometry(0, 0, 500, 500)
        # self.move(300, 150)

        self.movie = QMovie("images/drag_and_drop.gif")
        self.movie.start()

        self.gif_label = QLabel(self)
        self.gif_label.setMovie(self.movie)
        # self.gif_label.move(-100, -100)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.setDropAction(Qt.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            event.setDropAction(Qt.CopyAction)
            event.accept()
            links = []

            for url in event.mimeData().urls():
                if url.isLocalFile():  # checking if url
                    links.append(str(url.toLocalFile()))
                else:  # meaning --> a website or other url
                    links.append(str(url.toString()))

            self.addItems(links)
            self.movie.stop()  # Stop the movie
        else:
            event.ignore()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    list_box_widget = ListBoxWidget()
    list_box_widget.show()
    sys.exit(app.exec_())