import sys
from PyQt5.QtWidgets import QApplication, QTreeWidget, QTreeWidgetItem

# Create a list of engines to display
engines = [    {        'name': 'Engine 1',        'type': 'Turbojet',        'thrust': 10000,        'weight': 1000    },    {        'name': 'Engine 2',        'type': 'Turbofan',        'thrust': 20000,        'weight': 2000    }]

# Create the QApplication and QTreeWidget
app = QApplication(sys.argv)
tree = QTreeWidget()

# Set the header labels for the tree
tree.setHeaderLabels(['Name', 'Type', 'Thrust', 'Weight'])

# Add a top-level item for each engine
for engine in engines:
    # Create a QTreeWidgetItem for the engine
    item = QTreeWidgetItem([engine['name'], engine['type'], str(engine['thrust']), str(engine['weight'])])

    # Set additional data for the item using setData
    item.setData(0, 0, engine['name'])
    item.setData(1, 0, engine['type'])
    item.setData(2, 0, engine['thrust'])
    item.setData(3, 0, engine['weight'])

    # Add the item to the tree
    tree.addTopLevelItem(item)

# Set the style sheet for the tree widget
tree.setStyleSheet('''
    QTreeWidget {
        font-family: sans-serif;
        font-size: 14px;
        color: white;
        background-color: #333;
        border: 2px solid #444;
        gridline-color: #666;
    }
    QTreeWidget::item {
        padding: 5px;
        margin: 0px;
    }
    QTreeWidget::item:hover {
        background-color: #555;
    }
    QTreeWidget::item:selected {
        background-color: #777;
    }
    QTreeWidget::item:selected:active {
        background-color: #999;
    }
    QTreeWidget::item:selected:!active {
        background-color: #bbb;
    }
    QTreeWidget::indicator {
        width: 16px;
        height: 16px;
    }
    QTreeWidget::indicator:unchecked {
        border: 1px solid white;
    }
    QTreeWidget::indicator:unchecked:hover {
        border: 1px solid #aaa;
    }
    QTreeWidget::indicator:unchecked:pressed {
        border: 1px solid #555;
    }
    QTreeWidget::indicator:checked {
        background-color: white;
    }
    QTreeWidget::indicator:checked:hover {
        background-color: #aaa;
    }
    QTreeWidget::indicator:checked:pressed {
        background-color: #555;
    }
QTreeWidget::indicator:indeterminate {
        background-color: white;
        border: 1px dotted white;
    }
    QTreeWidget::indicator:indeterminate:hover {
        background-color: #aaa;
        border: 1px dotted #aaa;
    }
    QTreeWidget::indicator:indeterminate:pressed {
        background-color: #555;
        border: 1px dotted #555;
    }
    QTreeWidget::branch {
        background: transparent;
    }
    QTreeWidget::branch:closed:has-children {
        image: none;
        border: 0px;
    }
    QTreeWidget::branch:open:has-children {
        image: none;
        border: 0px;
    }
    QTreeWidget::branch:has-children:!has-siblings:closed,
    QTreeWidget::branch:closed:has-children:has-siblings {
        image: none;
        border: 0px;
    }
    QTreeWidget::branch:open:has-children:!has-siblings,
    QTreeWidget::branch:open:has-children:has-siblings  {
        image: none;
        border: 0px;
    }
''')

# Show the tree widget
tree.show()

# Run the application loop
sys.exit(app.exec_())