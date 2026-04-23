"""
Reusable log-type toggle row for Whiskers GUI pages.
"""

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QSizePolicy, QWidget

from GUI.config import active_dark_green


class LogTypeSelector(QWidget):
    """Button row that tracks Access/Auth/Firewall selection state."""

    selection_changed = pyqtSignal(str, bool)

    def __init__(self, *, default_access: bool = True, parent=None) -> None:
        super().__init__(parent)
        self._states = {"Access": False, "Auth": False, "Firewall": False}
        self._buttons: dict[str, QPushButton] = {}

        row = QHBoxLayout(self)
        label = QLabel("Log Types:")
        label.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        row.addWidget(label, stretch=0)

        for name in ("Access", "Auth", "Firewall"):
            button = QPushButton(name)
            button.setSizePolicy(
                QSizePolicy.Policy.Expanding,
                QSizePolicy.Policy.Fixed,
            )
            button.clicked.connect(lambda _checked=False, n=name: self.toggle(n))
            row.addWidget(button, stretch=1)
            self._buttons[name] = button

        if default_access:
            self.set_selected("Access", True)

    def toggle(self, name: str) -> None:
        self.set_selected(name, not self._states.get(name, False))

    def set_selected(self, name: str, selected: bool) -> None:
        if name not in self._states:
            return
        self._states[name] = selected
        button = self._buttons[name]
        button.setStyleSheet(f"color: {active_dark_green};" if selected else "")
        self.selection_changed.emit(name, selected)

    def is_selected(self, name: str) -> bool:
        return bool(self._states.get(name, False))

    def selected_states(self) -> dict[str, bool]:
        return self._states.copy()
