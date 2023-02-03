import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QGridLayout, QPushButton, QWidget


class WinAPIButtonWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # Create a central widget
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        # Create a grid layout
        layout = QGridLayout()
        central_widget.setLayout(layout)

        # Create a list of 19 WinAPI functions
        winapi_functions = [
            "CreateWindowExA", "CreateWindowExW", "CreateWindowA", "CreateWindowW",
            "DefWindowProcA", "DefWindowProcW", "DestroyWindow", "GetMessageA",
            "GetMessageW", "PostMessageA", "PostMessageW", "TranslateMessage",
            "DispatchMessageA", "DispatchMessageW", "PeekMessageA", "PeekMessageW",
            "GetWindowLongA", "GetWindowLongW", "SetWindowLongA", "SetWindowLongW"
        ]

        # Create a button for each function and add it to the grid layout
        row = 0
        column = 0
        for i, winapi_function in enumerate(winapi_functions):
            button = QPushButton(winapi_function)
            button.setStyleSheet("""
                QPushButton {
                    font-family: sans-serif;
                    border-radius: 5px;
                    font-size: 19px;
                    padding: 15px;
                    margin: 10px;
                    color: #87CEFA;
                    background-color: #333;
                    border: 2px solid #444;
                }
                QPushButton:hover {
                    background-color: #555;
                }
                QPushButton:pressed {
                    background-color: #666;
                }
            """)
            layout.addWidget(button, row, column)
            column += 1
            if column == 4:
                column = 0
                row += 1


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = WinAPIButtonWindow()
    win.show()
    sys.exit(app.exec_())