import time

from PyQt5.QtCore import QUrl
from PyQt5.QtGui import QMovie
from PyQt5.QtWidgets import QApplication, QLabel

app = QApplication([])
label = QLabel()
movie = QMovie("file_scan.gif")
label.setMovie(movie)
label.show()
movie.start()

# Wait for a few seconds
time.sleep(5)

# Stop the movie
movie.stop()

app.exec_()