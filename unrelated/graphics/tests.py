import sys
import random
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
import pyqtgraph as pg


class PlotWidget(QWidget):
    def __init__(self):
        super().__init__()

        # Create a plot widget
        self.plot = pg.PlotWidget()

        # Set the plot background color
        self.plot.setBackground((255, 255, 255))

        # Add the plot to the layout
        layout = QVBoxLayout()
        layout.addWidget(self.plot)
        self.setLayout(layout)

        # Create a timer to update the plot
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_plot)
        self.timer.start(1000)

        # Create a plot data object
        self.plot_data = []

    def update_plot(self):
        # Generate a random data point
        data_point = random.randint(0, 10)

        # Add the data point to the plot data list
        self.plot_data.append(data_point)

        # Limit the plot data to the last 100 points
        if len(self.plot_data) > 100:
            self.plot_data = self.plot_data[-100:]

        # Update the plot
        self.plot.clear()
        self.plot.plot(self.plot_data, pen=(255, 0, 0))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # Set the window title
        self.setWindowTitle('PyQtGraph Example')

        # Create the plot widget
        self.plot_widget = PlotWidget()

        # Set the central widget of the main window
        self.setCentralWidget(self.plot_widget)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
