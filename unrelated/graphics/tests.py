import sys
from PyQt5.QtWidgets import QApplication, QLabel, QFrame, QHBoxLayout
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt

# Create an instance of QApplication
app = QApplication(sys.argv)

# Create a QLabel with rich text formatting
label = QLabel("This is an error message.")
exclamation = QLabel("<p style='color:red;font-size:30px'>&#x2757;</p>")
exclamation.setTextFormat(Qt.RichText)

# Set the font to an error font
font = app.font()
font.setWeight(QFont.DemiBold)
font.setPointSize(30)
label.setFont(font)

# Create a horizontal layout and add the label and exclamation mark
layout = QHBoxLayout()
layout.addWidget(label)
layout.addWidget(exclamation)

# Create a QFrame container widget and set the layout
container = QFrame()
container.setLayout(layout)
print("got here")

# Show the container widget
container.show()

# Run the application loop
sys.exit(app.exec_())
