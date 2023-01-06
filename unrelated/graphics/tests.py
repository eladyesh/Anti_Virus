from PyQt5.QtWidgets import QApplication, QSpinBox

app = QApplication([])

# create a spin box
spin_box = QSpinBox()

# set the range and step size
spin_box.setRange(0, 100)
spin_box.setSingleStep(5)

# set the starting value
spin_box.setValue(50)

# set the suffix and prefix
spin_box.setPrefix("Number of hashes match: ")

# set the wrap mode
spin_box.setWrapping(True)

spin_box.show()
app.exec_()