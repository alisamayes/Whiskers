"""SQL injection / query tampering detector."""

from __future__ import annotations

from typing import List
import pandas as pd
from .base import BaseDetector, ThreatAlert


SUSPECT_SUBSTRINGS = [
    " or 1=1",
    " or \"1\"=\"1",
    "'--",
    " union select ",
    " drop table ",
    "../",
    "%2e%2e%2f",
    ";--",
]


class SqlInjectionDetector(BaseDetector):
    """Detects likely SQL injection attempts based on request paths/query strings."""

    kind = "sql_injection"
    description = "Detects SQLi-style payloads in request paths or query strings"

    def __init__(self, threshold: int = 3, time_window: str = "5min"):
        """
        Args:
            threshold: Number of suspicious requests per IP per time window to alert.
            time_window: Pandas time window string.
        """
        super().__init__(threshold)
        self.time_window = time_window

    def is_suspicious(self, path: str) -> bool:
        lower = path.lower()
        return any(token in lower for token in SUSPECT_SUBSTRINGS)

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        alerts: List[ThreatAlert] = []

        if df.empty or "path" not in df.columns:
            return alerts

        suspicious = df[df["path"].apply(self.is_suspicious)].copy()
        if suspicious.empty:
            return alerts

        suspicious = suspicious.set_index("timestamp")

        counts = (
            suspicious
            .groupby(["ip", pd.Grouper(freq=self.time_window)])["path"]
            .size()
        )
        flagged = counts[counts >= self.threshold]

        for (ip, time), count in flagged.items():
            alerts.append(
                ThreatAlert(
                    ip=ip,
                    timestamp=time,
                    kind=self.kind,
                    count=int(count),
                    confidence=0.9,
                )
            )

        return alerts

