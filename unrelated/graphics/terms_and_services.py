from PyQt5.QtWidgets import QApplication, QDialog, QLabel, QPlainTextEdit, QVBoxLayout, QHBoxLayout, QPushButton, \
    QCheckBox
from PyQt5.QtGui import QFont, QColor, QPalette
from PyQt5.QtCore import Qt


class TermsAndServicesDialog(QDialog):
    def __init__(self, bool, parent=None):
        super().__init__(parent)
        self.bool = bool
        self.setWindowTitle("Terms and Services Agreement")
        self.setFixedSize(600, 500)
        self.setWindowModality(Qt.ApplicationModal)
        self.setModal(True)
        self.initUI()

    def initUI(self):
        vbox = QVBoxLayout()

        label = QLabel("Terms and Services", self)
        label.setFont(QFont('Arial', 20, QFont.Bold))
        vbox.addWidget(label)

        terms = "Terms and Services\n\n1. Introduction\n\nThese terms and conditions constitute a legally binding agreement between you and [Your Company Name]. By accessing or using our services, you agree to be bound by these terms and conditions. If you do not agree with any of these terms and conditions, you may not use our services.\n\n2. Use of Our Services\n\nOur services may only be used for lawful purposes and in compliance with all applicable laws and regulations. You may not use our services for any illegal or unauthorized purpose nor may you, in the use of our services, violate any laws in your jurisdiction."
        text_edit = QPlainTextEdit(self)
        text_edit.setPlainText(terms)
        text_edit.setReadOnly(True)
        text_edit.setStyleSheet('background-color: white; color: black; font-size: 12px; border: none')
        vbox.addWidget(text_edit)

        hbox = QHBoxLayout()
        self.checkbox = QCheckBox("I agree to the terms and services", self)
        hbox.addWidget(self.checkbox)

        palette = self.palette()
        palette.setColor(QPalette.Button, QColor(47, 131, 247))
        palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        self.setPalette(palette)

        button_accept = QPushButton("Accept", self)
        button_accept.setStyleSheet(
            'background-color: #2F83F7; color: white; font-size: 14px; padding: 8px 10px; border-radius: 5px; border: none')
        button_accept.clicked.connect(self.accept_terms)
        hbox.addWidget(button_accept)
        vbox.addLayout(hbox)

        self.setLayout(vbox)

    def accept_terms(self):
        if self.checkbox.isChecked():
            print("Terms accepted")
            self.accept()
        else:
            print("Please accept the terms and services")

    def reject(self):
        if self.bool:
            return None


def terms_and_service(bool):
    dialog = TermsAndServicesDialog(bool)
    dialog.exec_()