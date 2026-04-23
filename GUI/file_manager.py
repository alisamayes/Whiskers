"""
File-management helpers for Whiskers GUI.
"""

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QMessageBox,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
from simulator.log_manager import save_logs, shred_logs


_DEFAULT_SOURCES = {
    "access": {"name": "access", "path": "data/access.log", "format": "access"},
    "auth": {"name": "auth", "path": "data/auth.log", "format": "auth"},
    "firewall": {"name": "firewall", "path": "data/firewall.log", "format": "firewall"},
}


class FileManagerPage(QWidget):
    """Container page for managing configured log-file paths."""

    def __init__(self, whiskers_agent, parent=None):
        super().__init__(parent)
        self.whiskers = whiskers_agent

        self.main_layout = QVBoxLayout(self)
        self.directory_box = QVBoxLayout()

        self.access_selector = FileSelector(self.whiskers, "access")
        self.auth_selector = FileSelector(self.whiskers, "auth")
        self.firewall_selector = FileSelector(self.whiskers, "firewall")

        self.directory_box.addWidget(self.access_selector)
        self.directory_box.addWidget(self.auth_selector)
        self.directory_box.addWidget(self.firewall_selector)
        self.directory_box.addStretch(1)

        self.main_layout.addLayout(self.directory_box)


class FileSelector(QWidget):
    """
    A reusable widget that gives:
      - one row with log-type label + current path label
      - one row with Save / Load / Shred buttons

    It is used to select a file for a given type of log.
    Load opens a file explorer and updates the configured source path.
    Save and Shred buttons are present but intentionally unconnected for now.
    """

    path_changed = pyqtSignal(str, str)

    def __init__(self, whiskers_agent, log_type: str, parent=None):
        super().__init__(parent)
        self.whiskers = whiskers_agent
        self.log_type = log_type.lower().strip()
        self.data = self.resolve_data_dict()

        root = QVBoxLayout(self)
        info_line = QHBoxLayout()
        button_line = QHBoxLayout()

        self.type_label = QLabel(f"{self.data['name']} log:")
        self.path_label = QLabel(self.data["path"])
        self.path_label.setWordWrap(True)

        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_FE)
        self.load_button = QPushButton("Load")
        self.load_button.clicked.connect(self.load_FE)
        self.shred_button = QPushButton("Shred")
        self.shred_button.clicked.connect(self.shred_FE)

        info_line.addWidget(self.type_label, stretch=0)
        info_line.addWidget(self.path_label, stretch=1)

        button_line.addWidget(self.save_button)
        button_line.addWidget(self.load_button)
        button_line.addWidget(self.shred_button)
        button_line.addStretch(1)

        root.addLayout(info_line)
        root.addLayout(button_line)

    def resolve_data_dict(self) -> dict[str, str]:
        """Return the selected source dict, creating defaults when missing."""
        if self.log_type not in _DEFAULT_SOURCES:
            raise ValueError(f"Unsupported log type: {self.log_type}")

        attr_name = f"{self.log_type}_logs"
        sources = getattr(self.whiskers, attr_name, None)
        if sources is None:
            setattr(self.whiskers, attr_name, [])
            sources = getattr(self.whiskers, attr_name)
        if not sources:
            sources.append(_DEFAULT_SOURCES[self.log_type].copy())
        return sources[0]

    def load_FE(self) -> None:
        """
        Open a file explorer and allow user to select a file.
        Update the path label to show the new path and update data["path"].
        """
        start_path = self.data["path"]
        selected_path, _ = QFileDialog.getOpenFileName(
            self,
            f"Select {self.data['name']} log file",
            start_path,
            "Log Files (*.log *.txt);;All Files (*.*)",
        )
        if not selected_path:
            return
        self.load_and_update_path(selected_path)

    def load_and_update_path(self, path: str) -> None:
        if not path:
            self.path_label.setText(self.data["path"])
            return
        self.data["path"] = path
        self.path_label.setText(path)
        self.path_changed.emit(self.log_type, path)

    def save_FE(self) -> None:
        """
        Open a file explorer and allow user to navigate to a directory to save current log file for a given log type.
        """

        selected_path, _ = QFileDialog.getSaveFileName(
            self,
            f"Save {self.data['name']} log file",
            self.data["path"],  # initial path or default filename
            "Log Files (*.log *.txt);;All Files (*.*)",
        )
        if selected_path:
            save_logs(self.whiskers, [self.log_type, selected_path])

    def shred_FE(self) -> None:
        """
        Open a file explorer and allow user to navigate to a directory to shred a saved log file for a given log type.
        """
        selected_path, _ = QFileDialog.getOpenFileName(
            self,
            f"Shred {self.data['name']} log file",
            self.data["path"],
            "Log Files (*.log *.txt);;All Files (*.*)",
        )
        # Make confirmation dialog to ensure user wants to shred the log file.
        confirmation = QMessageBox.question(
            self,
            f"Shred {self.data['name']} log file",
            f"Are you sure you want to shred the log file {selected_path}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirmation == QMessageBox.StandardButton.Yes:
            shred_logs(self.whiskers, [self.log_type, selected_path])
        else:
            return