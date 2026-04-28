from __future__ import annotations

from typing import List

import pandas as pd

from ..base import BaseDetector, ThreatAlert


class FirewallEgressExfiltrationDetector(BaseDetector):
    """Detects egress exfiltration attacks."""

    kind = "firewall_egress_exfiltration"
    description = "Detects egress exfiltration attacks."

    def __init__(self, threshold: int = 10, session_gap_seconds: int = 60):
        """
        Initialize egress exfiltration detector.
        """
        super().__init__(threshold)
        self.session_gap_seconds = session_gap_seconds

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        if df.empty or "log_source" not in df.columns:
            return []
        work = df[df["log_source"] == "firewall"].copy()
        if work.empty:
            return []
        required = {"ip", "timestamp", "bytes_sent"}
        if not required.issubset(set(work.columns)):
            return []

        work = work.sort_values(["ip", "timestamp"]).reset_index(drop=True)
        gap = pd.Timedelta(seconds=self.session_gap_seconds)
        alerts: List[ThreatAlert] = []

        # Interpret threshold as bytes per burst (not event count).
        for ip, group in work.groupby("ip"):
            group = group.sort_values("timestamp").reset_index(drop=True)
            start = 0
            for i in range(1, len(group)):
                if group.loc[i, "timestamp"] - group.loc[i - 1, "timestamp"] > gap:
                    seg = group.iloc[start:i]
                    total_bytes = int(seg["bytes_sent"].sum())
                    if total_bytes >= self.threshold:
                        alerts.append(
                            ThreatAlert(
                                ip=str(ip),
                                timestamp=seg["timestamp"].max(),
                                kind=self.kind,
                                count=total_bytes,
                                confidence=0.88,
                            )
                        )
                    start = i

            seg = group.iloc[start:]
            total_bytes = int(seg["bytes_sent"].sum())
            if total_bytes >= self.threshold:
                alerts.append(
                    ThreatAlert(
                        ip=str(ip),
                        timestamp=seg["timestamp"].max(),
                        kind=self.kind,
                        count=total_bytes,
                        confidence=0.88,
                    )
                )

        return alerts
