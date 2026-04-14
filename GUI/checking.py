"""
Checking page for the Whiskers GUI.

Shows the same summary as CLI ``-c``: accuracy vs labels, user distribution, and
log-line source counts. Does **not** re-run detection — use the Detector tab first.
"""

from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QPushButton,
)
from analysis.stats import report_check_stats

class CheckingPage(QWidget):
    def __init__(self, whiskers_agent, parent=None):
        """Build the CHECK page UI and bind actions to the Whiskers engine."""
        super().__init__(parent)

        self.whiskers = whiskers_agent

        self.layout = QVBoxLayout()

        self.check_box = QVBoxLayout()

        self.check_button = QPushButton("CHECK")
        self.check_button.clicked.connect(self.run_check)
        self.check_box.addWidget(self.check_button)

        self.stats_box = QVBoxLayout()
        self.report_stats = QLabel("")
        self.report_stats.setWordWrap(True)
        self.info_label = QLabel("")
        self.info_stats = QLabel("")
        self.info_stats.setWordWrap(True)

        self.stats_box.addWidget(self.report_stats)
        self.stats_box.addWidget(self.info_label)
        self.stats_box.addWidget(self.info_stats)

        self.layout.addLayout(self.check_box)
        self.layout.addLayout(self.stats_box)
        self.setLayout(self.layout)

    def refresh_from_engine(self, w) -> None:
        """Show check-style summary from current engine state (no detection re-run)."""
        if not hasattr(w, "df") or w.df is None or w.df.empty:
            self.report_stats.setText(
                "(no parsed logs — run Detector after logs are available)"
            )
            self.info_stats.setText("")
            return
        try:
            w.update_true_attack_counts_from_df()
        except Exception as e:
            self.report_stats.setText(f"Error while reading true counts from dataframe:\n{e}")
            self.info_stats.setText("")
            return
        report = w.run_check_report()
        self.report_stats.setText(report)
        n = int(w.df.shape[0])
        self.info_stats.setText(
            f"{n} row(s) in merged dataframe (true counts refreshed from labels)."
        )

    def run_check(self) -> None:
        """Render check-report output from current in-memory detection snapshot."""
        w = getattr(self.window(), "whiskers", None)
        if w is None:
            self.report_stats.setText(
                "Error: Whiskers engine not attached to the main window."
            )
            self.info_stats.setText("")
            return

        if not hasattr(w, "df") or w.df is None or w.df.empty:
            self.report_stats.setText(
                "No parsed logs in memory. Run Detector first, then CHECK again."
            )
            self.info_stats.setText("")
            return

        try:
            w.update_true_attack_counts_from_df()
        except Exception as e:
            self.report_stats.setText(f"Error while reading true counts from dataframe:\n{e}")
            self.info_stats.setText("")
            return

        report = w.run_check_report()
        self.report_stats.setText(report)

        n = int(w.df.shape[0])
        self.info_stats.setText(
            f"{n} row(s) in current merged dataframe (same snapshot as last detection if unchanged)."
        )
