import sys
import PyQt6
from PyQt6.QtWidgets import QTabWidget, QWidget, QVBoxLayout, QLabel
from PyQt6.QtGui import QPixmap, QFont
from PyQt6.QtCore import Qt


class ApplicationWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Whiskers")
        self.setGeometry(200, 200, 600, 400)
        
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.tabs.addTab(HomePage(), "Home")

class HomePage(QWidget):
    def __init__(self):
         
        super().__init__()
        self.layout = QVBoxLayout()
        self.layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Logo label, temp image till i come up with something better
        self.logo_label = QLabel()
        self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        pixmap = QPixmap("assets/whiskers_logo.jpeg")
        if not pixmap.isNull():
            self.logo_label.setPixmap(pixmap.scaled(160, 160, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))

        # App name, temp till i come up with something remotely acceptable
        self.title_label = QLabel("Whiskers")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        self.title_label.setFont(title_font)

        # Optional subtitle
        self.subtitle_label = QLabel("Cybersecurity Log Analysis Detective Mouse!")
        self.subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle_font = QFont()
        subtitle_font.setPointSize(12)
        self.subtitle_label.setFont(subtitle_font)

        # Add widgets to layout
        self.layout.addWidget(self.logo_label)
        self.layout.addWidget(self.title_label)
        self.layout.addWidget(self.subtitle_label)

        self.setLayout(self.layout)