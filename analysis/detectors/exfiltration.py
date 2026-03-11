"""Data exfiltration / large-transfer detector."""

from __future__ import annotations

from typing import List
import pandas as pd
from .base import BaseDetector, ThreatAlert


class ExfiltrationDetector(BaseDetector):
    """Detects unusually large outbound data transfers per IP."""

    kind = "data_exfiltration"
    description = "Detects large volumes of bytes sent per IP over short windows"

    def __init__(self, threshold: int = 5_000_000, time_window: str = "10min"):
        """
        Args:
            threshold: Total bytes_sent per IP per time window to alert.
            time_window: Pandas time window string.
        """
        super().__init__(threshold)
        self.time_window = time_window

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        alerts: List[ThreatAlert] = []

        if df.empty or "bytes_sent" not in df.columns:
            return alerts

        tmp = df.sort_values("timestamp").set_index("timestamp")

        grouped = tmp.groupby("ip")["bytes_sent"].resample(self.time_window).sum()
        flagged = grouped[grouped >= self.threshold]

        for (ip, time), total_bytes in flagged.items():
            alerts.append(
                ThreatAlert(
                    ip=ip,
                    timestamp=time,
                    kind=self.kind,
                    count=int(total_bytes),
                    confidence=0.85,
                )
            )

        return alerts

