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
        """
        Initialize SYN flood detector.

        Args:
            threshold: Minimum packets in a burst to alert.
            session_gap_seconds: Gap in seconds that starts a new burst.
        """
        super().__init__(threshold)
        self.session_gap_seconds = session_gap_seconds

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        """
        Detect SYN-flood-like bursts from one source IP.

        A burst is a sequence of denied TCP events where consecutive rows are no
        more than ``session_gap_seconds`` apart. A burst triggers when total
        packet count reaches ``threshold``.

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

        required = {"ip", "timestamp", "packets"}
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

        # Sessionise per IP: a flood burst has high packet volume in short time.
        for ip, group in work.groupby("ip"):
            group = group.sort_values("timestamp").reset_index(drop=True)
            session_start_idx = 0

            for i in range(1, len(group)):
                if group.loc[i, "timestamp"] - group.loc[i - 1, "timestamp"] > gap:
                    session = group.iloc[session_start_idx:i]
                    pkt_total = int(session["packets"].sum())
                    if pkt_total >= self.threshold:
                        alerts.append(
                            ThreatAlert(
                                ip=str(ip),
                                timestamp=session["timestamp"].max(),
                                kind=self.kind,
                                count=pkt_total,
                                confidence=0.85,
                            )
                        )
                    session_start_idx = i

            # Final session for this IP
            session = group.iloc[session_start_idx:]
            pkt_total = int(session["packets"].sum())
            if pkt_total >= self.threshold:
                alerts.append(
                    ThreatAlert(
                        ip=str(ip),
                        timestamp=session["timestamp"].max(),
                        kind=self.kind,
                        count=pkt_total,
                        confidence=0.85,
                    )
                )

        return alerts
