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
        """
        Initialize firewall SSH brute-force detector.

        Args:
            threshold: Minimum number of denied SSH attempts in a burst.
            session_gap_seconds: Gap in seconds that starts a new burst.
        """
        super().__init__(threshold)
        self.session_gap_seconds = session_gap_seconds

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        """
        Detect blocked SSH brute-force bursts from one source IP.

        A burst is a sequence of denied events to destination port 22 where
        consecutive rows are no more than ``session_gap_seconds`` apart.

        Args:
            df: Parsed firewall/common-schema dataframe.

        Returns:
            List of ThreatAlert objects (one per detected burst).
        """
        alerts: List[ThreatAlert] = []
        if df.empty:
            return alerts
        if "log_source" in df.columns:
            df = df[df["log_source"] == "firewall"]
            if df.empty:
                return alerts

        required = {"ip", "timestamp", "dst_port"}
        if not required.issubset(set(df.columns)):
            return alerts

        work = df.copy()
        # Prefer explicit action if present; otherwise fall back to status==403.
        if "action" in work.columns:
            work = work[work["action"].astype(str).str.upper() == "DENY"]
        elif "status" in work.columns:
            work = work[work["status"] == 403]
        if "protocol" in work.columns:
            work = work[work["protocol"].astype(str).str.lower() == "tcp"]
        work = work[work["dst_port"] == 22]
        if work.empty:
            return alerts

        work = work.sort_values(["ip", "timestamp"]).reset_index(drop=True)
        gap = pd.Timedelta(seconds=self.session_gap_seconds)

        # Sessionise per IP: a brute-force burst is many denied SSH attempts quickly.
        for ip, group in work.groupby("ip"):
            group = group.sort_values("timestamp").reset_index(drop=True)
            session_start_idx = 0

            for i in range(1, len(group)):
                if group.loc[i, "timestamp"] - group.loc[i - 1, "timestamp"] > gap:
                    session = group.iloc[session_start_idx:i]
                    if len(session) >= self.threshold:
                        alerts.append(
                            ThreatAlert(
                                ip=str(ip),
                                timestamp=session["timestamp"].max(),
                                kind=self.kind,
                                count=int(len(session)),
                                confidence=0.8,
                            )
                        )
                    session_start_idx = i

            # Final session for this IP
            session = group.iloc[session_start_idx:]
            if len(session) >= self.threshold:
                alerts.append(
                    ThreatAlert(
                        ip=str(ip),
                        timestamp=session["timestamp"].max(),
                        kind=self.kind,
                        count=int(len(session)),
                        confidence=0.8,
                    )
                )

        return alerts
