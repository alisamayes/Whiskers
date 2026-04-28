from __future__ import annotations

from typing import List

import pandas as pd

from ..base import BaseDetector, ThreatAlert


class FirewallEgressExfiltrationDetector(BaseDetector):
    """Detects egress exfiltration attacks."""

    kind = "firewall_egress_exfiltration"
    description = "Detects egress exfiltration attacks."

    def __init__(self, threshold: int = 5_000_000, session_gap_seconds: int = 60):
        """
        Initialize egress exfiltration detector.

        Args:
            threshold: Minimum total bytes in a burst to alert.
            session_gap_seconds: Gap in seconds that starts a new burst.
        """
        super().__init__(threshold)
        self.session_gap_seconds = session_gap_seconds

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        """
        Detect denied high-volume egress bursts from one source IP.

        A burst is a sequence of firewall events from one source IP where
        consecutive rows are no more than ``session_gap_seconds`` apart. A burst
        triggers when total ``bytes_sent`` reaches ``threshold``.

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

        required = {"ip", "timestamp", "bytes_sent"}
        if not required.issubset(set(df.columns)):
            return alerts

        work = df.copy()
        if "action" in work.columns:
            work = work[work["action"].astype(str).str.upper() == "DENY"]
        if work.empty:
            return alerts

        work = work.sort_values(["ip", "timestamp"]).reset_index(drop=True)
        gap = pd.Timedelta(seconds=self.session_gap_seconds)

        # Sessionise per IP: an exfil burst moves a large total byte volume.
        for ip, group in work.groupby("ip"):
            group = group.sort_values("timestamp").reset_index(drop=True)
            session_start_idx = 0

            for i in range(1, len(group)):
                if group.loc[i, "timestamp"] - group.loc[i - 1, "timestamp"] > gap:
                    session = group.iloc[session_start_idx:i]
                    total_bytes = int(session["bytes_sent"].sum())
                    if total_bytes >= self.threshold:
                        alerts.append(
                            ThreatAlert(
                                ip=str(ip),
                                timestamp=session["timestamp"].max(),
                                kind=self.kind,
                                count=total_bytes,
                                confidence=0.88,
                            )
                        )
                    session_start_idx = i

            # Final session for this IP
            session = group.iloc[session_start_idx:]
            total_bytes = int(session["bytes_sent"].sum())
            if total_bytes >= self.threshold:
                alerts.append(
                    ThreatAlert(
                        ip=str(ip),
                        timestamp=session["timestamp"].max(),
                        kind=self.kind,
                        count=total_bytes,
                        confidence=0.88,
                    )
                )

        return alerts
