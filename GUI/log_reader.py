"""
Log reader page for the Whiskers GUI.

This page provides a GUI log reader to view contents of one or more log files as opposed to needing to read on the CLI
with tools such as vi or nano, meaning the user would have to go outside the scope of Whiskers to check them.
"""

from parser.log_parser import read_text_lines_safe
from typing import TypedDict

from PyQt6.QtCore import QStringListModel
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListView,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from GUI.config import active_dark_green

# Tight vertical spacing for log lines (QListView default padding is roomy).
_LOG_VIEW_STYLE = """
    QListView {
        outline: none;
        font-family: Consolas, "Courier New", monospace;
        font-size: 11px;
    }
    QListView::item {
        padding: 0px 4px;
        margin: 0px;
    }
"""


class _LogToggleEntry(TypedDict):
    state: bool
    button: QPushButton


class LogReaderPage(QWidget):
    def __init__(self, whiskers_agent, parent=None):
        """
        Initialize the Detection Page widget.
        Sets up the page with a range of buttons that allow the user to handle the generation of new simulated log files with buttons as opposed
        to CLI commands, which should be more user friendly
        """
        super().__init__(parent)

        self.whiskers = whiskers_agent
        # Pyqt6 widgets

        self.main_layout = QVBoxLayout()
        # ============================================

        self.control_box = QVBoxLayout()
        self.reader_box = QVBoxLayout()
        # -----------------------------------------
        self.type_line = QHBoxLayout()
        self.types_label = QLabel("Log Types:")
        self.access_log_button = QPushButton("Access")
        self.access_log_button.clicked.connect(
            lambda: self.toggle_button(self.access_log_button)
        )
        self.auth_log_button = QPushButton("Auth")
        self.auth_log_button.clicked.connect(
            lambda: self.toggle_button(self.auth_log_button)
        )
        self.firewall_log_button = QPushButton("Firewall")
        self.firewall_log_button.clicked.connect(
            lambda: self.toggle_button(self.firewall_log_button)
        )

        self.type_line.addWidget(self.types_label)
        self.type_line.addWidget(self.access_log_button)
        self.type_line.addWidget(self.auth_log_button)
        self.type_line.addWidget(self.firewall_log_button)

        self.control_box.addLayout(self.type_line)
        # --------------------------------------------
        self.load_button = QPushButton("LOAD")
        self.load_button.clicked.connect(self.load_log_files)
        self.control_box.addWidget(self.load_button)

        self.log_view = QListView()
        self.log_view.setStyleSheet(_LOG_VIEW_STYLE)
        self._log_model = QStringListModel(self.log_view)
        self.log_view.setModel(self._log_model)
        self.reader_box.addWidget(self.log_view, stretch=1)

        self.main_layout.addLayout(self.control_box)
        self.main_layout.addLayout(self.reader_box, stretch=1)
        self.setLayout(self.main_layout)

        # ============================================

        # Class variables

        self.log_types: dict[str, _LogToggleEntry] = {
            "Access": {"state": False, "button": self.access_log_button},
            "Auth": {"state": False, "button": self.auth_log_button},
            "Firewall": {"state": False, "button": self.firewall_log_button},
        }

        self.toggle_button(self.access_log_button)

    def toggle_button(self, button: QPushButton):
        text = button.text()
        entry = self.log_types[text]

        entry["state"] = not entry["state"]
        button_ref = entry["button"]
        if entry["state"]:
            button_ref.setStyleSheet(f"color: {active_dark_green};")
        else:
            button_ref.setStyleSheet("")

    def load_log_files(self):
        """
        Allows the user to load one or more types of log files and display it in a log reader, as opposed to having
        to use the CLI with tools like nano or vi, which take the user outside the scope of Whiskers to check them.
        """

        log_files = []
        if self.log_types["Access"]["state"]:
            log_files.append("data/access.log")
        if self.log_types["Auth"]["state"]:
            log_files.append("data/auth.log")
        if self.log_types["Firewall"]["state"]:
            log_files.append("data/firewall.log")

        if not log_files:
            print("No log files selected. Please select at least one log type.")
            self._log_model.setStringList([])
            return

        all_lines = []
        for log_file in log_files:
            lines, error = read_text_lines_safe(log_file)
            if error:
                all_lines.append(f"[error] {error}\n")
                continue
            all_lines.extend(lines)

        self._log_model.setStringList(all_lines)
