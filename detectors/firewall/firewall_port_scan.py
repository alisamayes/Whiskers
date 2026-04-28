from __future__ import annotations

from typing import List

import pandas as pd

from ..base import BaseDetector, ThreatAlert


class FirewallPortScanDetector(BaseDetector):
    """Detects port scanning attacks."""

    kind = "firewall_port_scan"
    description = "Detects port scanning attacks."

    def __init__(self, threshold: int = 10, session_gap_seconds: int = 60):
        """
        Initialize port scan detector.
        """
        super().__init__(threshold)
        self.session_gap_seconds = session_gap_seconds

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        """Detect port scans as bursts of many distinct destination ports per source IP."""
        if df.empty or "log_source" not in df.columns:
            return []
        work = df[df["log_source"] == "firewall"].copy()
        if work.empty:
            return []
        required = {"ip", "timestamp", "dst_port"}
        if not required.issubset(set(work.columns)):
            return []

        work = work.sort_values(["ip", "timestamp"]).reset_index(drop=True)
        gap = pd.Timedelta(seconds=self.session_gap_seconds)
        alerts: List[ThreatAlert] = []

        for ip, group in work.groupby("ip"):
            group = group.sort_values("timestamp").reset_index(drop=True)
            start = 0
            for i in range(1, len(group)):
                if group.loc[i, "timestamp"] - group.loc[i - 1, "timestamp"] > gap:
                    seg = group.iloc[start:i]
                    unique_ports = int(seg["dst_port"].nunique())
                    if unique_ports >= self.threshold:
                        alerts.append(
                            ThreatAlert(
                                ip=str(ip),
                                timestamp=seg["timestamp"].max(),
                                kind=self.kind,
                                count=unique_ports,
                                confidence=0.9,
                            )
                        )
                    start = i

            seg = group.iloc[start:]
            unique_ports = int(seg["dst_port"].nunique())
            if unique_ports >= self.threshold:
                alerts.append(
                    ThreatAlert(
                        ip=str(ip),
                        timestamp=seg["timestamp"].max(),
                        kind=self.kind,
                        count=unique_ports,
                        confidence=0.9,
                    )
                )

        return alerts
