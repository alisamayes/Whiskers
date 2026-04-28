"""Detect SYN flood attacks from firewall logs."""

from __future__ import annotations

from typing import List

import pandas as pd

from ..base import BaseDetector, ThreatAlert


class FirewallSynFloodDetector(BaseDetector):
    """Detects SYN flood attacks."""

    kind = "firewall_syn_flood"
    description = "Detects SYN flood attacks."

    def __init__(self, threshold: int = 2000, session_gap_seconds: int = 2):
        # Interpret threshold as total packets within a burst.
        super().__init__(threshold)
        self.session_gap_seconds = session_gap_seconds

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        if df.empty or "log_source" not in df.columns:
            return []
        work = df[df["log_source"] == "firewall"].copy()
        if work.empty:
            return []
        required = {"ip", "timestamp", "packets"}
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
                    pkt_total = int(seg["packets"].sum())
                    if pkt_total >= self.threshold:
                        alerts.append(
                            ThreatAlert(
                                ip=str(ip),
                                timestamp=seg["timestamp"].max(),
                                kind=self.kind,
                                count=pkt_total,
                                confidence=0.85,
                            )
                        )
                    start = i

            seg = group.iloc[start:]
            pkt_total = int(seg["packets"].sum())
            if pkt_total >= self.threshold:
                alerts.append(
                    ThreatAlert(
                        ip=str(ip),
                        timestamp=seg["timestamp"].max(),
                        kind=self.kind,
                        count=pkt_total,
                        confidence=0.85,
                    )
                )

        return alerts
