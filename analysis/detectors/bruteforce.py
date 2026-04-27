"""Brute force attack detector."""

from __future__ import annotations

from typing import List

import pandas as pd

from .base import BaseDetector, ThreatAlert


class BruteForceDetector(BaseDetector):
    """Detects brute force attacks on login endpoints."""

    kind = "access_brute_force"
    description = "Detects repeated failed login attempts (401 on /login)"

    def __init__(self, threshold: int = 5, session_gap_seconds: int = 60):
        """
        Initialize brute force detector.

        Args:
            threshold: Minimum number of failed attempts within a burst to alert.
            session_gap_seconds: Gap in seconds between attempts that starts a new burst.
        """
        super().__init__(threshold)
        self.session_gap_seconds = session_gap_seconds

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        """
        Detect brute force attacks by identifying bursts of failed login attempts.
        Uses configurable threshold and time window for flexible ML-based detection.

        Args:
            df: Parsed access log dataframe.

        Returns:
            List of ThreatAlert objects (one per detected burst).
        """
        alerts: List[ThreatAlert] = []
        if df.empty:
            return alerts
        if "log_source" in df.columns:
            df = df[df["log_source"] == "access"]
            if df.empty:
                return alerts

        # Filter for failed login attempts (behavioral detection, no use of classification/count)
        failed = df[
            (df["path"] == "/login")
            & (df["status"] == 401)
            & (df["method"] == "POST")  # Brute force typically uses POST
        ].copy()

        if failed.empty:
            return alerts

        failed = failed.sort_values(["ip", "timestamp"]).reset_index(drop=True)
        gap = pd.Timedelta(seconds=self.session_gap_seconds)

        # Sessionise per IP: a "burst" is a sequence of failed logins with gaps <= session_gap_seconds
        for ip, group in failed.groupby("ip"):
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
                                count=len(session),
                                confidence=0.95,
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
                        count=len(session),
                        confidence=0.95,
                    )
                )

        return alerts
