import hashlib
import sys

import qdarkstyle
import requests
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QPalette, QColor
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, \
    QPushButton, QTextEdit


class PasswordCheckerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Password Checker')
        self.setFixedSize(600, 400)
        self.setStyleSheet(qdarkstyle.load_stylesheet())
        self.setWindowFlags(Qt.FramelessWindowHint)

        main_widget = QWidget()
        layout = QVBoxLayout(main_widget)

        title_bar_widget = QWidget()
        title_bar_layout = QHBoxLayout(title_bar_widget)
        title_bar_layout.setContentsMargins(0, 0, 0, 0)
        title_bar_widget.setStyleSheet(qdarkstyle.load_stylesheet())

        title_label = QLabel('Password Checker')
        title_label.setFont(QFont('Arial', 12, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet(qdarkstyle.load_stylesheet())

        close_button = QPushButton('X')
        close_button.clicked.connect(self.close)
        close_button.setStyleSheet(qdarkstyle.load_stylesheet())
        close_button.setMaximumWidth(30)

        title_bar_layout.addWidget(title_label)
        title_bar_layout.addWidget(close_button)

        password_widget = QWidget()
        password_layout = QVBoxLayout(password_widget)
        password_layout.setContentsMargins(20, 20, 20, 20)

        password_label = QLabel('Enter your password:')
        password_label.setFont(QFont('Arial', 10))
        password_input = QLineEdit()
        password_input.setEchoMode(QLineEdit.Password)
        password_input.setStyleSheet(qdarkstyle.load_stylesheet())

        check_button = QPushButton('Check')
        check_button.clicked.connect(lambda: self.check_password(password_input.text()))
        check_button.setStyleSheet(qdarkstyle.load_stylesheet())

        result_text = QTextEdit()
        result_text.setReadOnly(True)
        result_text.setStyleSheet(qdarkstyle.load_stylesheet())

        password_layout.addWidget(password_label)
        password_layout.addWidget(password_input)
        password_layout.addWidget(check_button)
        password_layout.addWidget(result_text)

        layout.addWidget(title_bar_widget)
        layout.addWidget(password_widget)

        self.setCentralWidget(main_widget)

        palette = self.palette()
        palette.setColor(QPalette.Window, QColor("#222222"))
        self.setPalette(palette)

        self.setStyleSheet(qdarkstyle.load_stylesheet())

        self.drag_position = None

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.drag_position = event.globalPos() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.LeftButton and self.drag_position:
            self.move(event.globalPos() - self.drag_position)
            event.accept()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.drag_position = None

    def check_password(self, password):
        if not password:
            self.update_result('Enter a password')
            return

        sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        first5_char, tail = sha1password[:5], sha1password[5:]
        url = 'https://api.pwnedpasswords.com/range/' + first5_char
        response = requests.get(url)
        if response.status_code != 200:
            result = f'Error fetching: {response.status_code}, check the API and try again'
        else:
            hashes = (line.split(':') for line in response.text.splitlines())
            count = next((count for h, count in hashes if h == tail), 0)
            if count:
                result = f'{password} was found {count} times. You should change your password.'
            else:
                result = f'{password} was not found. It\'s safe.'
        self.update_result(result)

    def update_result(self, result):
        result_text = self.findChild(QTextEdit)
        result_text.setText(result)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PasswordCheckerApp()
    window.show()
    sys.exit(app.exec_())
