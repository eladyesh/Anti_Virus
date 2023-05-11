from PyQt5.QtWidgets import QApplication, QDialog, QLabel, QPlainTextEdit, QVBoxLayout, QHBoxLayout, QPushButton, \
    QCheckBox, QLineEdit, QTextEdit, QScrollBar
from PyQt5.QtGui import QFont, QColor, QPalette, QTextCursor, QTextCharFormat
from PyQt5.QtCore import Qt

from PyQt5.QtWidgets import QApplication, QDialog, QLabel, QPlainTextEdit, QVBoxLayout, QHBoxLayout, QPushButton, \
    QCheckBox, QLineEdit
from PyQt5.QtGui import QFont, QColor, QPalette, QIcon
from PyQt5.QtCore import Qt


def create_scroll_bar():
    scrollBar = QScrollBar()
    scrollBar.setOrientation(Qt.Vertical)
    scrollBar.setMinimum(0)
    scrollBar.setMaximum(100)
    scrollBar.setSingleStep(1)
    scrollBar.setPageStep(10)
    scrollBar.setValue(50)

    # Customize the appearance of the scroll bar

    scrollBar_stylesheet = """
                    QScrollBar:vertical {
                        border: none;
                        background: #eee;
                        width: 15px;
                        margin: 0px 0px 0px 0px;
                    }

                    QScrollBar::handle:vertical {
                        background: #ccc;
                        min-height: 20px;
                        border-radius: 5px;
                    }

                    QScrollBar::add-line:vertical {
                        background: none;
                        height: 0px;
                        subcontrol-position: bottom;
                        subcontrol-origin: margin;
                    }

                    QScrollBar::sub-line:vertical {
                        background: none;
                        height: 0px;
                        subcontrol-position: top;
                        subcontrol-origin: margin;
                    }

                    QScrollBar::up-arrow:vertical, QScrollBar::down-arrow:vertical {
                        border: none;
                        width: 0px;
                        height: 0px;
                        background: none;
                    }

                    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                        background: none;
                    }
                """

    scrollBar.setStyleSheet(scrollBar_stylesheet)
    return scrollBar


class TermsAndServicesDialog(QDialog):
    def __init__(self, bool, parent=None):
        super().__init__(parent)
        self.bool = bool
        self.setWindowTitle("Services and Instructions Agreement")
        self.setFixedSize(600, 500)
        self.setWindowModality(Qt.ApplicationModal)
        self.setModal(True)
        self.initUI()

    def initUI(self):
        vbox = QVBoxLayout()

        label = QLabel("Services and Instructions", self)
        label.setFont(QFont('Arial', 20, QFont.Bold))
        vbox.addWidget(label)

        self.terms_textedit = QPlainTextEdit(self)
        self.terms_textedit.setVerticalScrollBar(create_scroll_bar())
        self.terms_textedit.setReadOnly(True)
        self.terms_textedit.setStyleSheet('background-color: white; color: black; font-size: 12px; border: none')
        vbox.addWidget(self.terms_textedit)

        hbox_search = QHBoxLayout()
        self.search_textedit = QLineEdit(self)
        self.search_textedit.setPlaceholderText("Search terms and services...")
        self.search_textedit.textChanged.connect(self.search_terms)

        search_icon = QIcon("images/search.png")
        search_button = QPushButton()
        search_button.setFixedWidth(35)
        search_button.setIcon(search_icon)
        search_button.clicked.connect(self.search_terms)
        hbox_search.addWidget(self.search_textedit)
        hbox_search.addWidget(search_button)
        vbox.addLayout(hbox_search)

        hbox_checkbox = QHBoxLayout()
        self.checkbox = QCheckBox("I agree to the terms and services", self)
        hbox_checkbox.addWidget(self.checkbox)

        button_accept = QPushButton("Accept", self)
        button_accept.setStyleSheet(
            'background-color: #2F83F7; color: white; font-size: 14px; padding: 8px 10px; border-radius: 5px; border: none')
        button_accept.clicked.connect(self.accept_terms)
        hbox_checkbox.addWidget(button_accept)
        vbox.addLayout(hbox_checkbox)

        self.setLayout(vbox)

        # Load terms and services from a string
        self.terms = """

1. Introduction

These instructions and services are necessary for the use of this application. Please be aware to accept them at the end

2. Remove From System:
Remove any analysis files that are relevant to the suspected file.
System will be restarted and you will have to close the virtual machine manually.

3. Virtual Machine and Dynamic Analysis

In order to start the dynamic analysis, you will have to press the 'Start Virtual Machine' button.
Then, you will have to wait till the machine is fully on.
Only then, you can drag a file to the application, and press the 'Start Dynamic Analysis' button.
You will get a notification on the status bar when the report is ready.

4. Static and Hash Analysis
If you wish to directly load the file for static and hash analysis, press the "Load" button for both
of these features, since they will be locked.

5. Fuzzy Hashing Analysis
The file in the system will be compared to close to 50,000,000 fuzzy hashes in order to find
if the file contains malicious code. if you exit the window, the scan will continue.
And when you return, the scan will be shown again.

6. Directory Analysis
If you wish to pick this option, you will choose a directory, and each of the files
will be sent to Virus Total. If more than 5 engines of the website found any of the files as malicious, 
You will see them in the list in the right of the screen

7. IP Analysis
If you wish to pick this option, each of the IP's from your DNS cache will be uploaded to Virus Total,
and if more than 5 engines found the IP as malicious, the system will block that IP, 
and the system will present it to the right of the screen. When the scanning is over,
the system will open a different process to block the IP's that were found malicious. If you agree
to the opening, these IP's will now be blocked.

8. Further Notice
Every Analysis done in this application will be deleted COMPLETELY once you move to a new window.
Please be aware and not upset. 
That is because once a new window has been shown, Analysis that has been done before is deleted off the screen

ENJOY !!!!
"""

        # Set the initial content of the text edit
        self.terms_textedit.setPlainText(self.terms)

    def search_terms(self):
        """
        Search for the given text in the terms and services.
        """
        text = self.search_textedit.text()
        if text:
            cursor = self.terms_textedit.document().find(text)
            if not cursor.isNull():
                self.terms_textedit.setTextCursor(cursor)
                self.terms_textedit.ensureCursorVisible()
                cursor.select(QTextCursor.WordUnderCursor)
                highlight = QTextEdit.ExtraSelection()
                highlight.cursor = cursor
                highlight.format.setBackground(QColor("yellow"))
                self.terms_textedit.setExtraSelections([highlight])
            else:
                self.terms_textedit.setExtraSelections([])
        else:
            self.terms_textedit.setExtraSelections([])

    def accept_terms(self):
        if self.checkbox.isChecked():
            print("Terms accepted")
            self.accept()
        else:
            print("Please accept the services and instructions")

    def reject(self):
        if self.bool:
            return None


def terms_and_service(bool):
    dialog = TermsAndServicesDialog(bool)
    dialog.exec_()
