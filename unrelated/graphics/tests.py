from PyQt5.QtWidgets import QListWidget, QListWidgetItem

# Create a QListWidget
listWidget = QListWidget()

# Create a QListWidgetItem for the header
headerItem = QListWidgetItem()
headerItem.setText("Header")

# Set the header item for the QListWidget
listWidget.setHeaderItem(headerItem)