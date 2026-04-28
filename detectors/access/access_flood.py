"""Request flood/DoS detector."""

from __future__ import annotations

from typing import List

import pandas as pd

from ..base import BaseDetector, ThreatAlert


class FloodDetector(BaseDetector):
    """Detects request flood (DoS) attacks."""

    kind = "access_request_flood"
    description = "Detects unusual request spike patterns (high request rate)"

    def __init__(self, threshold: int = 100, session_gap_seconds: int = 5):
        """
        Initialize flood detector.

        Args:
            threshold: Number of requests within a flood burst to alert.
            session_gap_seconds: Gap in seconds between requests that starts a new burst.
        """
        super().__init__(threshold)
        self.session_gap_seconds = session_gap_seconds

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        """
        Detect request floods by looking for high request rates per IP.

        Args:
            df: Parsed access log dataframe.

        Returns:
            List of ThreatAlert objects.
        """
        alerts: List[ThreatAlert] = []

        if df.empty:
            return alerts
        if "log_source" in df.columns:
            df = df[df["log_source"] == "access"]
            if df.empty:
                return alerts

        df = df.sort_values(["ip", "timestamp"]).copy()
        gap = pd.Timedelta(seconds=self.session_gap_seconds)

        # Sessionise per IP: a flood is a sequence of closely spaced requests
        for ip, group in df.groupby("ip"):
            group = group.sort_values("timestamp")
            session_start_idx = 0

            for i in range(1, len(group)):
                prev_ts = group.iloc[i - 1]["timestamp"]
                cur_ts = group.iloc[i]["timestamp"]

                if cur_ts - prev_ts > gap:
                    session = group.iloc[session_start_idx:i]
                    if len(session) >= self.threshold:
                        alerts.append(
                            ThreatAlert(
                                ip=ip,
                                timestamp=session["timestamp"].max(),
                                kind=self.kind,
                                count=int(len(session)),
                                confidence=0.90,
                            )
                        )
                    session_start_idx = i

            # Final session for this IP
            session = group.iloc[session_start_idx:]
            if len(session) >= self.threshold:
                alerts.append(
                    ThreatAlert(
                        ip=ip,
                        timestamp=session["timestamp"].max(),
                        kind=self.kind,
                        count=int(len(session)),
                        confidence=0.90,
                    )
                )

        return alerts
