"""
Detection page for the Whiskers GUI.

This page provides a button-driven way to run the same detection pipeline that the CLI
would run for the `-d/--detect` command.
"""

from PyQt6.QtWidgets import QLabel, QPushButton, QVBoxLayout, QWidget

from command_processing import set_detect_sources
from GUI.log_type_selector import LogTypeSelector


class DetectionPage(QWidget):
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

        self.detect_box = QVBoxLayout()
        # -----------------------------------------
        self.log_type_selector = LogTypeSelector(default_access=True)
        self.log_type_selector.selection_changed.connect(self.apply_log_toggle)
        self.detect_box.addWidget(self.log_type_selector)
        # --------------------------------------------
        self.detect_button = QPushButton("DETECT")
        self.detect_button.clicked.connect(self.detect)
        self.detect_box.addWidget(self.detect_button)
        # Keep controls compact at the top of the page.
        self.detect_box.addStretch(1)

        # ============================================

        self.stats_box = QVBoxLayout()
        # --------------------------------------------
        self.true_attack_stats = QLabel("")
        self.stats_box.addWidget(self.true_attack_stats)

        self.main_layout.addLayout(self.detect_box, stretch=0)
        self.main_layout.addLayout(self.stats_box, stretch=1)
        self.setLayout(self.main_layout)

        # ============================================

    def toggle_detection_modes(self) -> bool:
        """Use CLI-equivalent source selection for GUI detection toggles."""
        engine = getattr(self.window(), "whiskers", None) or self.whiskers
        if engine is None:
            return False

        states = self.log_type_selector.selected_states()
        set_detect_sources(
            engine,
            access=bool(states.get("Access", False)),
            auth=bool(states.get("Auth", False)),
            firewall=bool(states.get("Firewall", False)),
        )
        return True

    def apply_log_toggle(self, log_type: str, enabled: bool) -> None:
        """Keep engine detection sources in sync with GUI toggles."""
        _ = (log_type, enabled)
        self.toggle_detection_modes()

    def detect(self):
        """Run parse + true-count refresh + detection for selected sources."""
        states = self.log_type_selector.selected_states()
        if not any(states.values()):
            self.true_attack_stats.setText("Please select at least one detection mode")
            return

        # Always resync to current toggle state so stale sources don't leak in.
        if not self.toggle_detection_modes():
            self.true_attack_stats.setText(
                "Error: Whiskers engine not attached to the main window."
            )
            return
        w = getattr(self.window(), "whiskers", None) or self.whiskers

        w.run_detection_pipeline()

        self.update_stats(w)

    def update_stats(self, whiskers_engine):
        """Render detected and true attack counts from engine state."""
        detected = getattr(whiskers_engine, "detected_attack_counts", {})
        true_counts = getattr(whiskers_engine, "true_attack_counts", {})
        show_access = bool(getattr(whiskers_engine, "access_logs", []))
        show_auth = bool(getattr(whiskers_engine, "auth_logs", []))
        show_firewall = bool(getattr(whiskers_engine, "firewall_logs", []))

        def include_kind(kind: str) -> bool:
            if kind.startswith("access_"):
                return show_access
            if kind.startswith("auth_"):
                return show_auth
            if kind.startswith("firewall_"):
                return show_firewall
            return kind == "ml_anomaly"

        detected_lines = ["\n--------------- ATTACK DETECTION COUNTS ---------------"]
        if isinstance(detected, dict):
            for k, v in detected.items():
                if not include_kind(k):
                    continue
                detected_lines.append(f"- {k}: {v}")
        else:
            detected_lines.append("(unavailable)")

        true_lines = ["\n--------------- TRUE ATTACK COUNTS ---------------"]
        if isinstance(true_counts, dict):
            for k, v in true_counts.items():
                if not include_kind(k):
                    continue
                true_lines.append(f"- {k}: {v}")
        else:
            true_lines.append("(unavailable)")

        self.true_attack_stats.setText("\n".join(detected_lines + true_lines))
