import sys
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QListWidget

class MainWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.list_widgets = {}
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.setLayout(layout)

        # Create a button for each list widget
        for i in range(3):
            button = QPushButton('+', self)
            button.setFixedSize(40, 40)
            button.clicked.connect(self.toggle_list_widget)
            layout.addWidget(button)
            self.list_widgets[button] = None

    def toggle_list_widget(self):
        button = self.sender()
        if self.list_widgets[button] is None:
            list_widget = QListWidget(self)
            self.list_widgets[button] = list_widget
            list_widget.show()
            button.setText('-')
        else:
            list_widget = self.list_widgets[button]
            list_widget.close()
            self.list_widgets[button] = None
            button.setText('+')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_widget = MainWidget()
    main_widget.show()
    sys.exit(app.exec_())
