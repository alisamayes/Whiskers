"""Data exfiltration / large-transfer detector."""

from __future__ import annotations

from typing import List

import pandas as pd

from .base import BaseDetector, ThreatAlert


class ExfiltrationDetector(BaseDetector):
    """Detects unusually large outbound data transfers per IP."""

    kind = "access_data_exfiltration"
    description = "Detects large volumes of bytes sent per IP over short windows"

    def __init__(self, threshold: int = 5_000_000, session_gap_seconds: int = 300):
        """
        Args:
            threshold: Total bytes_sent per IP within a burst to alert.
            session_gap_seconds: Gap in seconds between large responses that starts a new burst.
        """
        super().__init__(threshold)
        self.session_gap_seconds = session_gap_seconds

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        alerts: List[ThreatAlert] = []

        if df.empty or "bytes_sent" not in df.columns:
            return alerts

        tmp = df.sort_values(["ip", "timestamp"])
        gap = pd.Timedelta(seconds=self.session_gap_seconds)

        # Sessionise per IP: an exfil burst is a sequence of large transfers close together
        for ip, group in tmp.groupby("ip"):
            group = group.sort_values("timestamp")
            session_start_idx = 0

            for i in range(1, len(group)):
                prev_ts = group.iloc[i - 1]["timestamp"]
                cur_ts = group.iloc[i]["timestamp"]

                if cur_ts - prev_ts > gap:
                    session = group.iloc[session_start_idx:i]
                    total_bytes = session["bytes_sent"].sum()
                    if total_bytes >= self.threshold:
                        alerts.append(
                            ThreatAlert(
                                ip=ip,
                                timestamp=session["timestamp"].max(),
                                kind=self.kind,
                                count=int(total_bytes),
                                confidence=0.85,
                            )
                        )
                    session_start_idx = i

            # Final session for this IP
            session = group.iloc[session_start_idx:]
            total_bytes = session["bytes_sent"].sum()
            if total_bytes >= self.threshold:
                alerts.append(
                    ThreatAlert(
                        ip=ip,
                        timestamp=session["timestamp"].max(),
                        kind=self.kind,
                        count=int(total_bytes),
                        confidence=0.85,
                    )
                )

        return alerts
