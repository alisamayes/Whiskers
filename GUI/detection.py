"""
Detection page for the Whiskers GUI.

This page provides a button-driven way to run the same detection pipeline that the CLI
would run for the `-d/--detect` command.
"""

from PyQt6.QtWidgets import QLabel, QPushButton, QVBoxLayout, QWidget

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

        # ============================================

        self.stats_box = QVBoxLayout()
        # --------------------------------------------
        self.true_attack_stats = QLabel("")
        self.stats_box.addWidget(self.true_attack_stats)

        self.main_layout.addLayout(self.detect_box)
        self.main_layout.addLayout(self.stats_box)
        self.setLayout(self.main_layout)

        # ============================================

    def apply_log_toggle(self, log_type: str, enabled: bool) -> None:
        """Enable or disable one configured log source on the engine."""
        engine = getattr(self.window(), "whiskers", None) or self.whiskers
        if engine is None:
            return

        sources = {
            "Access": (
                "access_logs",
                {"name": "access", "path": "data/access.log", "format": "access"},
            ),
            "Auth": (
                "auth_logs",
                {"name": "auth", "path": "data/auth.log", "format": "auth"},
            ),
            "Firewall": (
                "firewall_logs",
                {"name": "firewall", "path": "data/firewall.log", "format": "firewall"},
            ),
        }

        if log_type not in sources:
            return

        attr, src = sources[log_type]
        setattr(engine, attr, [src] if enabled else [])

    def detect(self):
        """Run parse + true-count refresh + detection for selected sources."""
        # For now, run the same pipeline as CLI `-d/--detect` against the current
        # configured log sources on the Whiskers instance.
        w = getattr(self.window(), "whiskers", None)
        if w is None:
            self.true_attack_stats.setText(
                "Error: Whiskers engine not attached to the main window."
            )
            return

        w.run_detection_pipeline()

        self.update_stats(w)

    def update_stats(self, whiskers_engine):
        """Render detected and true attack counts from engine state."""
        detected = getattr(whiskers_engine, "detected_attack_counts", {})
        true_counts = getattr(whiskers_engine, "true_attack_counts", {})

        detected_lines = ["\n--------------- ATTACK DETECTION COUNTS ---------------"]
        if isinstance(detected, dict):
            for k, v in detected.items():
                detected_lines.append(f"- {k}: {v}")
        else:
            detected_lines.append("(unavailable)")

        true_lines = ["\n--------------- TRUE ATTACK COUNTS ---------------"]
        if isinstance(true_counts, dict):
            for k, v in true_counts.items():
                true_lines.append(f"- {k}: {v}")
        else:
            true_lines.append("(unavailable)")

        self.true_attack_stats.setText("\n".join(detected_lines + true_lines))
