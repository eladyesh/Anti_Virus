import sys
from PyQt5.QtWidgets import QApplication, QWidget, QHBoxLayout, QLabel

class MyWidget(QWidget):
    def __init__(self):
        super().__init__()

        # create the labels
        label_center = QLabel("Center")
        label_right = QLabel("Right")

        # create the horizontal layout
        hbox = QHBoxLayout(self)

        # add a stretchable space before the center label to push it to the center
        hbox.addStretch(1)

        # add the center label to the layout without stretch
        hbox.addWidget(label_center, 0)

        # add the right label to the layout without stretch
        hbox.addWidget(label_right, 0)

        # set a final stretchable space after the right label to push them to the left
        hbox.addStretch(1)

        # set the layout margin to 35px
        hbox.setContentsMargins(35, 0, 35, 0)

        # set a margin-left of 35px for the right label
        label_right.setStyleSheet("margin-left: 500px;")

        # set the layout for the widget
        self.setLayout(hbox)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    widget = MyWidget()
    widget.show()
    sys.exit(app.exec_())
