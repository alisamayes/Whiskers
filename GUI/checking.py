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

from analysis.stats import build_check_report


class CheckingPage(QWidget):
    def __init__(self, whiskers_agent, parent=None):
        super().__init__(parent)

        self.whiskers = whiskers_agent

        self.layout = QVBoxLayout()

        self.check_box = QVBoxLayout()
        self.intro = QLabel(
            "Uses the dataframe and detector results already in memory. "
            "Run Detector first, then CHECK (same idea as CLI -c — no models re-run)."
        )
        self.intro.setWordWrap(True)

        self.check_button = QPushButton("CHECK")
        self.check_button.clicked.connect(self.run_check)
        self.check_box.addWidget(self.intro)
        self.check_box.addWidget(self.check_button)

        self.stats_box = QVBoxLayout()
        self.report_label = QLabel("Latest run — check summary:")
        self.report_stats = QLabel("(no run yet)")
        self.report_stats.setWordWrap(True)
        self.info_label = QLabel("Dataframe:")
        self.info_stats = QLabel("")
        self.info_stats.setWordWrap(True)

        self.stats_box.addWidget(self.report_label)
        self.stats_box.addWidget(self.report_stats)
        self.stats_box.addWidget(self.info_label)
        self.stats_box.addWidget(self.info_stats)

        self.layout.addLayout(self.check_box)
        self.layout.addLayout(self.stats_box)
        self.setLayout(self.layout)

    def run_check(self) -> None:
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

        report = build_check_report(
            w.true_attack_counts,
            w.detected_attack_counts,
            w.ips_that_attacked,
            profile_counts=getattr(w, "profile_counts", None),
            log_source_counts=getattr(w, "log_source_counts", None),
        )
        self.report_stats.setText(report)

        n = int(w.df.shape[0])
        self.info_stats.setText(
            f"{n} row(s) in current merged dataframe (same snapshot as last detection if unchanged)."
        )
