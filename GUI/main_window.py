from pathlib import Path

from PyQt6.QtCore import QObject, Qt, pyqtSignal
from PyQt6.QtGui import QCloseEvent, QFont, QIcon, QPixmap, QResizeEvent, QShowEvent
from PyQt6.QtWidgets import (
    QLabel,
    QMainWindow,
    QSizePolicy,
    QSystemTrayIcon,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from GUI.checking import CheckingPage
from GUI.detection import DetectionPage
from GUI.generation import GenPage
from GUI.log_reader import LogReaderPage
from GUI.file_manager import FileManagerPage

_ASSETS = Path(__file__).resolve().parent.parent / "assets"


class UiBridge(QObject):
    """Posted from the CLI thread; slots run on the Qt thread (queued connection)."""

    show_ui = pyqtSignal()


def load_logo_pixmap() -> QPixmap:
    for name in ("whiskers_logo.png", "whiskers_logo.jpeg", "whisker_logo_alt.jpeg"):
        path = _ASSETS / name
        if path.is_file():
            pm = QPixmap(str(path))
            if not pm.isNull():
                return pm
    return QPixmap()


def load_window_icon() -> QIcon:
    """Resolve icon next to this package (not CWD). Required for taskbar/tray on Windows."""
    for name in ("whiskers_logo.png", "whiskers_logo.jpeg", "whisker_logo_alt.jpeg"):
        path = _ASSETS / name
        if path.is_file():
            icon = QIcon(str(path))
            if not icon.isNull():
                return icon
    return QIcon()


class ApplicationWindow(QMainWindow):
    def __init__(self, whiskers_agent):
        super().__init__()
        self.whiskers = whiskers_agent
        self.setWindowTitle("Whiskers")
        self.setGeometry(200, 200, 600, 400)
        self.close_hides_only = False

        # Set icons to Whiskers logo (path vs. CWD — see load_window_icon)
        window_icon = load_window_icon()
        self.tray = QSystemTrayIcon(window_icon, self)
        self.tray.setVisible(True)
        self.tray.setToolTip("Whiskers")
        self.setWindowIcon(window_icon)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.home = HomePage()
        self.gen = GenPage(self.whiskers)
        self.detect = DetectionPage(self.whiskers)
        self.checking = CheckingPage(self.whiskers)
        self.reader = LogReaderPage(self.whiskers)
        self.file_manager = FileManagerPage(self.whiskers)
        self.tabs.addTab(self.home, "Home")
        self.tabs.addTab(self.gen, "Generator")
        self.tabs.addTab(self.detect, "Detector")
        self.tabs.addTab(self.checking, "Checking")
        self.tabs.addTab(self.reader, "Log Reader")
        self.tabs.addTab(self.file_manager, "File Manager")
        
    def closeEvent(self, event: QCloseEvent | None) -> None:
        if event is None:
            return
        if self.close_hides_only:
            event.ignore()
            self.hide()
        else:
            super().closeEvent(event)


class HomePage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        self.logo_source = load_logo_pixmap()

        self.logo_label = QLabel()
        self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.logo_label.setMinimumSize(1, 1)
        self.logo_label.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )

        self.title_label = QLabel("Whiskers")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        self.title_label.setFont(title_font)
        self.title_label.setSizePolicy(
            QSizePolicy.Policy.Preferred,
            QSizePolicy.Policy.Fixed,
        )

        self.subtitle_label = QLabel("Cybersecurity Log Analysis Detective Mouse!")
        self.subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.subtitle_label.setWordWrap(True)
        subtitle_font = QFont()
        subtitle_font.setPointSize(12)
        self.subtitle_label.setFont(subtitle_font)
        self.subtitle_label.setSizePolicy(
            QSizePolicy.Policy.Preferred,
            QSizePolicy.Policy.Minimum,
        )

        # Logo row absorbs almost all extra space; text rows stay compact
        layout.addWidget(self.logo_label, stretch=1)
        layout.addWidget(
            self.title_label, stretch=0, alignment=Qt.AlignmentFlag.AlignHCenter
        )
        layout.addWidget(
            self.subtitle_label, stretch=0, alignment=Qt.AlignmentFlag.AlignHCenter
        )

    def showEvent(self, event: QShowEvent | None) -> None:
        super().showEvent(event)
        self.scale_logo_to_label()

    def resizeEvent(self, event: QResizeEvent | None) -> None:
        super().resizeEvent(event)
        self.scale_logo_to_label()

    def scale_logo_to_label(self) -> None:
        if self.logo_source.isNull():
            return
        w, h = self.logo_label.width(), self.logo_label.height()
        if w < 2 or h < 2:
            return
        scaled = self.logo_source.scaled(
            w,
            h,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self.logo_label.setPixmap(scaled)
