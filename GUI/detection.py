"""
Detection page for the Whiskers GUI.

This page provides a button-driven way to run the same detection pipeline that the CLI
would run for the `-d/--detect` command.
"""

from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QLineEdit,
)

from simulator.auth_log_simulator import (
    AUTH_CLASS_SSH_BRUTEFORCE,
    AUTH_CLASS_SSH_USER_ENUM,
    AUTH_CLASS_SUDO_BRUTEFORCE,
    AUTH_CLASS_PRIVLAGE_ESCALATION_CHAIN,
)
from GUI.config import active_dark_green


class DetectionPage(QWidget):
    def __init__(self, whiskers_agent, parent = None):
        """
        Initialize the Detection Page widget.
        Sets up the page with a range of buttons that allow the user to handle the generation of new simulated log files with buttons as opposed
        to CLI commands, which should be more user friendly
        """
        super().__init__(parent)


        self.whiskers = whiskers_agent
        #Pyqt6 widgets

        self.layout = QVBoxLayout()
        # ============================================

        self.detect_box = QVBoxLayout()
        # -----------------------------------------
        self.type_line = QHBoxLayout()
        self.types_label = QLabel("Log Types:")
        self.access_log_button = QPushButton("Access")
        self.access_log_button.clicked.connect(
            lambda: self.toggle_button(self.access_log_button))
        self.auth_log_button = QPushButton("Auth")
        self.auth_log_button.clicked.connect(
            lambda: self.toggle_button(self.auth_log_button))
        self.firewall_log_button = QPushButton("Firewall")
        self.firewall_log_button.clicked.connect(
            lambda: self.toggle_button(self.firewall_log_button))
        
        self.type_line.addWidget(self.types_label)
        self.type_line.addWidget(self.access_log_button)
        self.type_line.addWidget(self.auth_log_button)
        self.type_line.addWidget(self.firewall_log_button)

        self.detect_box.addLayout(self.type_line)
        #--------------------------------------------
        self.detect_button = QPushButton("DETECT")
        self.detect_button.clicked.connect(self.detect)
        self.detect_box.addWidget(self.detect_button)

        # ============================================

        self.stats_box = QVBoxLayout()
        #--------------------------------------------
        self.true_attack_label = QLabel("Latest run — detection summary:")
        self.true_attack_stats = QLabel("(no run yet)")

        self.stats_box.addWidget(self.true_attack_label)
        self.stats_box.addWidget(self.true_attack_stats)


        self.layout.addLayout(self.detect_box)
        self.layout.addLayout(self.stats_box)
        self.setLayout(self.layout)

        #============================================

        # Class variables

        self.log_types = {
            "Access" : {"state" :False , "button" : self.access_log_button},
            "Auth" : {"state" :False , "button" : self.auth_log_button},
            "Firewall": {"state" :False , "button" : self.firewall_log_button},
        }

        self.toggle_button(self.access_log_button)

        
    def toggle_button(self, button: QPushButton):
        text = button.text()
        entry = self.log_types[text]


        entry["state"] = not entry["state"]
        if entry["state"]:
            entry["button"].setStyleSheet(f"color: {active_dark_green};")
        else:
            entry["button"].setStyleSheet("")

        self.apply_log_toggle(text, entry["state"])

    def apply_log_toggle(self, log_type: str, enabled: bool) -> None:
        engine = getattr(self.window(), "whiskers", None) or self.whiskers
        if engine is None:
            return

        sources = {
            "Access": (
                "access_logs",
                {"name": "access", "path": "data/access.log", "format": "whiskers_access"},
            ),
            "Auth": (
                "auth_logs",
                {"name": "auth", "path": "data/auth.log", "format": "whiskers_auth"},
            ),
            "Firewall": (
                "firewall_logs",
                {"name": "firewall", "path": "data/firewall.log", "format": "whiskers_firewall"},
            ),
        }

        if log_type not in sources:
            return

        attr, src = sources[log_type]
        setattr(engine, attr, [src] if enabled else [])



    def detect(self):
        # For now, run the same pipeline as CLI `-d/--detect` against the current
        # configured log sources on the Whiskers instance.
        w = getattr(self.window(), "whiskers", None)
        if w is None:
            self.true_attack_stats.setText("Error: Whiskers engine not attached to the main window.")
            self.actor_stats.setText("")
            return

        w.prepare_dataframe()
        w.update_true_attack_counts_from_df()
        w.run_detection_models()

        self.update_stats(w)

    def update_stats(self, whiskers_engine):
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
