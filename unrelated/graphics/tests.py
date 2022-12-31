import sys
from PyQt5.QtWidgets import QApplication, QFrame, QVBoxLayout, QLabel, QScrollArea

# Create the application
app = QApplication(sys.argv)

# Create a vertical layout
layout = QVBoxLayout()

# Add some labels to the layout
for i in range(20):
    label = QLabel(f"Label {i}")
    layout.addWidget(label)

# Create a frame to hold the layout
frame = QFrame()
frame.setLayout(layout)

# Create a scroll area and set the frame as its widget
scroll_area = QScrollArea()
scroll_area.setWidget(frame)

# Show the scroll area
scroll_area.show()

# Run the application
sys.exit(app.exec_())