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

        Args:
            threshold: Minimum number of unique destination ports in a burst.
            session_gap_seconds: Gap in seconds that starts a new burst.
        """
        super().__init__(threshold)
        self.session_gap_seconds = session_gap_seconds

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        """
        Detect firewall port scans using burst sessionization per source IP.

        A scan burst is a sequence of firewall-denied TCP events from one source IP
        where consecutive rows are no more than ``session_gap_seconds`` apart. A
        burst triggers when the number of unique destination ports reaches
        ``threshold``.

        Args:
            df: Parsed firewall/common-schema dataframe.

        Returns:
            List of ThreatAlert objects (one per detected scan burst).
        """
        alerts: List[ThreatAlert] = []
        if df.empty:
            return []
        if "log_source" in df.columns:
            df = df[df["log_source"] == "firewall"]
            if df.empty:
                return alerts

        required = {"ip", "timestamp", "dst_port"}
        if not required.issubset(set(df.columns)):
            return alerts

        work = df.copy()
        if "action" in work.columns:
            work = work[work["action"].astype(str).str.upper() == "DENY"]
        if "protocol" in work.columns:
            work = work[work["protocol"].astype(str).str.lower() == "tcp"]
        if work.empty:
            return alerts

        work = work.sort_values(["ip", "timestamp"]).reset_index(drop=True)
        gap = pd.Timedelta(seconds=self.session_gap_seconds)

        # Sessionise per IP: a scan burst probes many destination ports quickly.
        for ip, group in work.groupby("ip"):
            group = group.sort_values("timestamp").reset_index(drop=True)
            session_start_idx = 0

            for i in range(1, len(group)):
                if group.loc[i, "timestamp"] - group.loc[i - 1, "timestamp"] > gap:
                    session = group.iloc[session_start_idx:i]
                    unique_ports = int(session["dst_port"].nunique())
                    if unique_ports >= self.threshold:
                        alerts.append(
                            ThreatAlert(
                                ip=str(ip),
                                timestamp=session["timestamp"].max(),
                                kind=self.kind,
                                count=unique_ports,
                                confidence=0.9,
                            )
                        )
                    session_start_idx = i

            # Final session for this IP
            session = group.iloc[session_start_idx:]
            unique_ports = int(session["dst_port"].nunique())
            if unique_ports >= self.threshold:
                alerts.append(
                    ThreatAlert(
                        ip=str(ip),
                        timestamp=session["timestamp"].max(),
                        kind=self.kind,
                        count=unique_ports,
                        confidence=0.9,
                    )
                )

        return alerts
