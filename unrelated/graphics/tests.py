from PyQt5.QtWidgets import QApplication, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget
import sys


class TreeDemo(QWidget):
    def __init__(self):
        super().__init__()

        self.tree = QTreeWidget()
        self.tree.setHeaderLabel("Items")

        for i in range(10):
            item = QTreeWidgetItem(self.tree, ["Item " + str(i)])
            for j in range(5):
                subitem = QTreeWidgetItem(item, ["Subitem " + str(j)])

        layout = QVBoxLayout()
        layout.addWidget(self.tree)
        self.setLayout(layout)

        self.calculate_tree_height()

    def calculate_tree_height(self):
        num_items = self.tree.topLevelItemCount()
        item_height = self.tree.sizeHintForRow(0)
        header_height = self.tree.header().height()
        scrollbar_height = self.tree.verticalScrollBar().sizeHint().height()
        total_height = item_height * num_items + header_height + scrollbar_height
        self.tree.setMinimumHeight(total_height)

    def add_item(self, text):
        item = QTreeWidgetItem(self.tree, [text])
        self.calculate_tree_height()

    def remove_item(self, item):
        parent = item.parent()
        index = parent.indexOfChild(item)
        parent.removeChild(item)
        if parent.childCount() == 0:
            self.tree.invisibleRootItem().removeChild(parent)
        self.calculate_tree_height()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = TreeDemo()
    window.setGeometry(300, 300, 300, 400)
    window.show()

    # Add some items
    window.add_item("New Item 1")
    window.add_item("New Item 2")

    # Remove an item
    item = window.tree.invisibleRootItem().child(0).child(1)
    window.remove_item(item)

    sys.exit(app.exec_())
