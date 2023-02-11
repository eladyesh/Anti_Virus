from PyQt5.QtCore import Qt
from PyQt5.QtGui import QBrush
from PyQt5.QtWidgets import QApplication, QTreeWidget, QTreeWidgetItem, QMainWindow
import sys


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.tree_imports = QTreeWidget(self)
        self.tree_imports.setHeaderLabels(['WinAPI Functions'])
        self.tree_imports.setStyleSheet("""
            QTreeView {
                font-family: sans-serif;
                font-size: 14px;
                color: #87CEFA;
                background-color: #333;
                border: 2px solid #444;
                gridline-color: #666;
            }

            QTreeView::branch:has-children:!has-siblings:closed,
            QTreeView::branch:closed:has-children:has-siblings {
                border-image: none;
                color: #87CEFA;
            }

            QTreeView::branch:has-children:!has-siblings:open,
            QTreeView::branch:open:has-children:has-siblings  {
                border-image: none;
                color: #87CEFA;
            }

            QTreeView::branch:selected {
                color: white;
            }

            QTreeView::indicator {
                color: #87CEFA;
            }

            QTreeView::item {
                padding: 5px;
                margin: 1px;
            }

            QTreeView::item:hover {
                background-color: #555;
            }

            QTreeView::item:selected {
                background-color: #777;
            }
            QTableWidget::item:selected:active {
                background-color: #999;
            }
            QTableWidget::item:selected:!active {
                background-color: #bbb;
            }

        """)

        # Create 20 WinAPI functions
        winapi_functions = ['CreateWindowEx', 'DefWindowProc', 'DestroyWindow', 'GetMessage', 'TranslateMessage',
                            'DispatchMessage', 'PostQuitMessage', 'RegisterClass', 'UnregisterClass', 'LoadCursor',
                            'LoadIcon', 'ShowWindow', 'UpdateWindow', 'GetDC', 'ReleaseDC', 'BeginPaint', 'EndPaint',
                            'InvalidateRect', 'ValidateRect', 'SetFocus']

        # Add WinAPI functions to the QTreeWidget
        for function in winapi_functions:
            item = QTreeWidgetItem(self.tree_imports, [function])

        self.tree_imports.itemClicked.connect(self.handle_item_click)

        # Make the first item red
        red = QBrush(Qt.red)
        item = self.tree_imports.topLevelItem(0)
        item.setForeground(0, red)

        self.setCentralWidget(self.tree_imports)
        self.show()

    def handle_item_click(self, item):
        function_name = item.text(0)
        if function_name == "CreateWindowEx":
            if item.childCount() == 0:

                info_item = QTreeWidgetItem(item, ["Wow ....", "what a great function"])
                info_item_rest = QTreeWidgetItem(item, ["what a great function"])

                red = QBrush(Qt.red)
                info_item.setForeground(0, red)

                # Add similar conditions for other functions
                item.addChild(info_item)
                item.addChild(info_item_rest)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    sys.exit(app.exec_())
