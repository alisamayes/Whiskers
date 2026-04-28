"""Firewall-level SSH brute force detector.

This flags bursts of firewall *DENY* events to destination port 22. Unlike auth-log
SSH brute force, this does not prove password failures occurred; it only shows
repeated blocked connection attempts.
"""

from __future__ import annotations

from typing import List

import pandas as pd

from ..base import BaseDetector, ThreatAlert


class FirewallSshBruteforceDetector(BaseDetector):
    """Detect SSH brute force attempts observed at the firewall."""

    kind = "firewall_ssh_bruteforce"
    description = "Bursts of firewall DENY events to TCP/22"

    def __init__(self, threshold: int = 25, session_gap_seconds: int = 60):
        super().__init__(threshold)
        self.session_gap_seconds = session_gap_seconds

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        if df.empty or "log_source" not in df.columns:
            return []
        work = df[df["log_source"] == "firewall"].copy()
        if work.empty:
            return []
        required = {"ip", "timestamp", "dst_port"}
        if not required.issubset(set(work.columns)):
            return []

        # Prefer explicit action if present; otherwise fall back to status==403.
        if "action" in work.columns:
            work = work[work["action"].astype(str).str.upper() == "DENY"]
        elif "status" in work.columns:
            work = work[work["status"] == 403]

        work = work[work["dst_port"] == 22]
        if work.empty:
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
                    if len(seg) >= self.threshold:
                        alerts.append(
                            ThreatAlert(
                                ip=str(ip),
                                timestamp=seg["timestamp"].max(),
                                kind=self.kind,
                                count=int(len(seg)),
                                confidence=0.8,
                            )
                        )
                    start = i

            seg = group.iloc[start:]
            if len(seg) >= self.threshold:
                alerts.append(
                    ThreatAlert(
                        ip=str(ip),
                        timestamp=seg["timestamp"].max(),
                        kind=self.kind,
                        count=int(len(seg)),
                        confidence=0.8,
                    )
                )

        return alerts
