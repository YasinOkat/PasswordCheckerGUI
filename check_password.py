import hashlib
import sys

import requests
from PyQt5.QtCore import Qt, QEvent
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon, QCursor
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, \
    QPushButton, QTextEdit, QProgressBar, QStyle
from qt_material import apply_stylesheet


class PasswordCheckerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Password Checker')
        self.setFixedSize(600, 400)
        self.setWindowFlags(Qt.FramelessWindowHint)

        self.drag_position = None

        main_widget = QWidget()
        layout = QVBoxLayout(main_widget)

        title_bar_widget = QWidget()
        title_bar_layout = QHBoxLayout(title_bar_widget)
        title_bar_layout.setContentsMargins(0, 0, 0, 0)
        title_bar_widget.setObjectName("title_bar_widget")

        title_label = QLabel('Password Checker')
        title_label.setFont(QFont('Arial', 12, QFont.Bold))
        title_label.setAlignment(Qt.AlignLeft)

        title_bar_layout.addWidget(title_label)

        layout.addWidget(title_bar_widget)

        password_widget = QWidget()
        password_layout = QVBoxLayout(password_widget)
        password_layout.setContentsMargins(20, 20, 20, 20)

        password_label = QLabel('Enter your password:')
        password_label.setFont(QFont('Arial', 10))
        password_input = QLineEdit()
        password_input.setStyleSheet("color: #1de9b6;")

        check_button = QPushButton('Check')
        check_button.clicked.connect(lambda: self.check_password(password_input.text()))

        result_text = QTextEdit()
        result_text.setReadOnly(True)

        strength_label = QLabel('Strength:')
        strength_label.setFont(QFont('Arial', 10))
        strength_indicator = QProgressBar()
        strength_indicator.setMinimum(0)
        strength_indicator.setMaximum(100)
        strength_indicator.setValue(0)
        strength_indicator.setTextVisible(True)

        brute_force_label = QLabel('The time it will take to hack with brute force:')
        brute_force_label.setFont(QFont('Arial', 10))
        self.brute_force_value = QLabel('')
        self.brute_force_value.setFont(QFont('Arial', 10))

        password_layout.addWidget(password_label)
        password_layout.addWidget(password_input)
        password_layout.addWidget(check_button)
        password_layout.addWidget(result_text)
        password_layout.addWidget(strength_label)
        password_layout.addWidget(strength_indicator)
        password_layout.addWidget(brute_force_label)
        password_layout.addWidget(self.brute_force_value)

        layout.addWidget(password_widget)

        self.setCentralWidget(main_widget)

        palette = self.palette()
        self.setPalette(palette)

        password_input.textChanged.connect(self.update_password_strength)

        self.create_title_bar_buttons()

    def create_title_bar_buttons(self):
        title_bar = self.findChild(QWidget, "title_bar_widget")

        minimize_button = QPushButton()
        minimize_button.setIcon(self.style().standardIcon(QStyle.SP_TitleBarMinButton))
        minimize_button.setStyleSheet("background-color: transparent; border: none;")

        minimize_button.setFixedSize(30, 30)
        minimize_button.setCursor(QCursor(Qt.PointingHandCursor))
        minimize_button.clicked.connect(self.showMinimized)
        minimize_button.installEventFilter(self)

        title_bar.layout().addWidget(minimize_button)

        close_button = QPushButton()
        close_button.setIcon(self.style().standardIcon(QStyle.SP_TitleBarCloseButton))
        close_button.setStyleSheet("background-color: transparent; border: none;")
        close_button.setFixedSize(30, 30)
        close_button.setCursor(QCursor(Qt.PointingHandCursor))
        close_button.clicked.connect(self.close)
        close_button.installEventFilter(self)

        title_bar.layout().addWidget(close_button)

        close_button.setIcon(QIcon("resources/close_icon.png"))
        minimize_button.setIcon(QIcon("resources/minimize_icon.png"))

    def eventFilter(self, obj, event):
        if event.type() == QEvent.HoverEnter:
            obj.setStyleSheet("background-color: #1de9b6; border: none;")
        elif event.type() == QEvent.HoverLeave:
            obj.setStyleSheet("background-color: transparent; border: none")

        return super().eventFilter(obj, event)

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

        hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        first5_char, tail = hashed_password[:5], hashed_password[5:]

        url = 'https://api.pwnedpasswords.com/range/' + first5_char

        self.hide_progress_bar()
        self.show_progress_bar()
        response = requests.get(url)

        if response.status_code != 200:
            result = f'Error fetching: {response.status_code}, check the API and try again'
        else:
            hashes = (line.split(':') for line in response.text.splitlines())
            count = next((count for h, count in hashes if h == tail), 0)
            if count:
                result = f'The password "{password}" was found {count} times in compromised databases. It is highly ' \
                         f'recommended to change your password to ensure your account\'s security.'
            else:
                result = f'Congratulations! The password "{password}" was not found in any compromised databases. It ' \
                         f'appears to be safe and secure.'
        self.update_result(result)

    def update_result(self, result):
        result_text = self.findChild(QTextEdit)
        result_text.setText(result)

    def show_progress_bar(self):
        progress_bar = self.findChild(QProgressBar)
        progress_bar.setVisible(True)

    def hide_progress_bar(self):
        progress_bar = self.findChild(QProgressBar)
        progress_bar.setVisible(False)

    def update_password_strength(self, password):
        # Calculate password strength
        upper, lower, digit, symbols = False, False, False, False
        length = len(password)
        scaling_factor = 0.5 if length > 10 else length / 20
        length_strength = min(length, 10) * 10 * scaling_factor

        complexity_strength = 0

        if any(c.isupper() for c in password):
            complexity_strength += 10
            upper = True

        if any(c.islower() for c in password):
            complexity_strength += 10
            lower = True

        if any(c.isdigit() for c in password):
            complexity_strength += 10
            digit = True

        if any(not c.isalnum() and not c.isspace() for c in password):
            complexity_strength += 10
            symbols = True

        pattern_strength = 0
        patterns = [
            "0123456789",
            "abcdefghijklmnopqrstuvwxyz",
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm",
            "!@#$%^&*()_+",
        ]

        brute_force_time = "Unknown"

        if length < 12 and digit and not any([upper, lower, symbols]):
            brute_force_time = "Instantly"
        elif length in range(12, 19) and digit and not any([upper, lower, symbols]):
            brute_force_time = {
                12: "2 secs",
                13: "19 secs",
                14: "3 mins",
                15: "32 mins",
                16: "5 hours",
                17: "2 days",
                18: "3 weeks"
            }.get(length, "Unknown")

        elif length < 9 and lower and not any([upper, digit, symbols]):
            brute_force_time = "Instantly"
        elif length in range(9, 19) and lower and not any([upper, digit, symbols]):
            brute_force_time = {
                9: "10 secs",
                10: "4 mins",
                11: "2 hours",
                12: "2 days",
                13: "2 months",
                14: "4 years",
                15: "100 years",
                16: "3k years",
                17: "69k years",
                18: "2m years",
            }.get(length, "Unknown")

        elif length < 7 and lower and upper and not any([digit, symbols]):
            brute_force_time = "Instantly"
        elif length in range(7, 19) and upper and lower and not any([digit, symbols]):
            brute_force_time = {
                7: "2 secs",
                8: "2 mins",
                9: "1 hours",
                10: "3 days",
                11: "5 months",
                12: "24 years",
                13: "1k years",
                14: "64k years",
                15: "3m years",
                16: "173m years",
                17: "9bn years",
                18: "467bn years",
            }.get(length, "Unknown")

        elif length < 7 and lower and upper and digit and not any([symbols]):
            brute_force_time = "Instantly"
        elif length in range(7, 19) and upper and lower and digit and not any([symbols]):
            brute_force_time = {
                7: "7 secs",
                8: "7 mins",
                9: "7 hours",
                10: "3 weeks",
                11: "3 years",
                12: "200 years",
                13: "12k years",
                14: "750k years",
                15: "46m years",
                16: "3bn years",
                17: "179bn years",
                18: "11tn years",
            }.get(length, "Unknown")

        elif length < 7 and lower and upper and digit and symbols:
            brute_force_time = "Instantly"
        elif length in range(7, 19) and upper and lower and digit and symbols:
            brute_force_time = {
                7: "31 secs",
                8: "39 mins",
                9: "2 days",
                10: "5 months",
                11: "34 years",
                12: "3k years",
                13: "202k years",
                14: "16m years",
                15: "1bn years",
                16: "92bn years",
                17: "7tn years",
                18: "438tn years",
            }.get(length, "Unknown")

        if length > 18 and digit and not any([upper, symbols, lower]):
            brute_force_time = "More than 3 weeks"
        elif length > 18 and lower:
            brute_force_time = "More than 2m years"
        elif length > 18 and upper:
            brute_force_time = "More than 467bn years"
        elif length > 18 and digit and upper and lower:
            brute_force_time = "More than 11tn years"
        elif length > 18 and symbols:
            brute_force_time = "More than 438tn years"

        for pattern in patterns:
            if pattern in password.lower():
                pattern_strength -= 10

        if any(password.lower().count(char * 3) > 0 for char in password.lower()):
            pattern_strength -= 10

        complexity_strength += pattern_strength

        strength_score = int(length_strength + complexity_strength)

        strength_indicator = self.findChild(QProgressBar)

        if strength_score <= 40:
            strength_indicator.setValue(strength_score)
            strength_indicator.setStyleSheet("QProgressBar::chunk { background-color: #dc3545; }")
        elif strength_score <= 65:
            strength_indicator.setValue(strength_score)
            strength_indicator.setStyleSheet("QProgressBar::chunk { background-color: #ffc107; }")
        else:
            strength_indicator.setValue(strength_score)
            strength_indicator.setStyleSheet("QProgressBar::chunk { background-color: green; }")

        strength_indicator.setValue(strength_score)
        self.brute_force_value.setText(brute_force_time)


if __name__ == '__main__':
    app = QApplication(sys.argv)

    apply_stylesheet(app, theme='dark_teal.xml')
    window = PasswordCheckerApp()
    window.show()

    sys.exit(app.exec_())
