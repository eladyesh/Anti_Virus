import sys
from PyQt5.QtWidgets import QApplication, QTextEdit, QVBoxLayout, QWidget

app = QApplication(sys.argv)

window = QWidget()
layout = QVBoxLayout()

text = """
Variable name: result
Library name: winsock
Function name: connect
Parameters: s, address, ctypes.sizeof(address), port

==============PORT SCANNING==============
Trying to scan through ports [78, 79, 80]
Trying to connect to website ctypes.create_string_buffer(b'google.com\x00')
==============PORT SCANNING==============

==============REGISTRY CHANGE==============
Trying to add or change key 'SOFTWARE\\Classes\\CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\shell'
Trying to add key 'open\\command'
Trying to set key to 'C:\\Users\\IEUser\\Desktop\\research\\2023-01-20-malware-pers-21\\hack.exe'.encode('utf-8')
==============REGISTRY CHANGE==============
"""

text_widgets = text.split("\n\n")

for t in text_widgets:
    text_edit = QTextEdit()
    text_edit.setText(t)
    height = text_edit.document().size().height()
    print(height)
    text_edit.setStyleSheet("""
    QTextEdit {
    background-color: white;
    font-size: 25px;
    border: 5px solid purple;
    border-radius: 10px;
    padding: 10px;
    margin: 10px;
    }
    """)
    text_edit.setReadOnly(True)
    text_edit.setFixedHeight(250)
    layout.addWidget(text_edit)

window.setLayout(layout)
window.show()

sys.exit(app.exec_())






