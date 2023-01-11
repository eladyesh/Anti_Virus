from PyQt5 import QtGui
from PyQt5.QtWidgets import *

# Creating a light shade of purple color
light_purple = QtGui.QColor(255, 153, 255, 180)

# Creating a "cool" font
cool_font = QtGui.QFont("Comic Sans MS", 18)
cool_font.setItalic(True)

# Using the color and font
label = QLabel("This is a cool label with light purple color")
label.setStyleSheet("color: {}".format(light_purple.name()))
label.setFont(cool_font)