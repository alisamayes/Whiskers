"""
Log reader page for the Whiskers GUI.

This page provides a GUI log reader to view contents of one or more log files as opposed to needing to read on the CLI
with tools such as vi or nano, meaning the user would have to go outside the scope of Whiskers to check them.
"""

from parser.log_parser import read_text_lines_safe

from PyQt6.QtCore import QStringListModel
from PyQt6.QtWidgets import (
    QListView,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from GUI.log_type_selector import LogTypeSelector

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
        self.log_type_selector = LogTypeSelector(default_access=True)
        self.control_box.addWidget(self.log_type_selector)
        # --------------------------------------------
        self.load_button = QPushButton("LOAD")
        self.load_button.clicked.connect(self.load_log_files)
        self.control_box.addWidget(self.load_button)
        # Keep controls compact at the top of the page.
        self.control_box.addStretch(1)

        self.log_view = QListView()
        self.log_view.setStyleSheet(_LOG_VIEW_STYLE)
        self._log_model = QStringListModel(self.log_view)
        self.log_view.setModel(self._log_model)
        self.reader_box.addWidget(self.log_view, stretch=1)

        self.main_layout.addLayout(self.control_box, stretch=0)
        self.main_layout.addLayout(self.reader_box, stretch=1)
        self.setLayout(self.main_layout)

        # ============================================

    def load_log_files(self):
        """
        Allows the user to load one or more types of log files and display it in a log reader, as opposed to having
        to use the CLI with tools like nano or vi, which take the user outside the scope of Whiskers to check them.
        """

        log_files = []
        states = self.log_type_selector.selected_states()
        if states["Access"]:
            log_files.append("data/access.log")
        if states["Auth"]:
            log_files.append("data/auth.log")
        if states["Firewall"]:
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
