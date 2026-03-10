"""Brute force attack detector."""

from __future__ import annotations

from typing import List
import pandas as pd
from .base import BaseDetector, ThreatAlert


class BruteForceDetector(BaseDetector):
    """Detects brute force attacks on login endpoints."""

    kind = "brute_force"
    description = "Detects repeated failed login attempts (401 on /login)"

    def __init__(self, threshold: int = 10, time_window: str = "1min"):
        """
        Initialize brute force detector.
        
        Args:
            threshold: Number of failed attempts per time window to alert.
            time_window: Pandas time window string (e.g., '1min', '5min').
        """
        super().__init__(threshold)
        self.time_window = time_window

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        """
        Detect brute force attacks by looking for multiple 401 errors on /login.
        
        Args:
            df: Parsed access log dataframe.
            
        Returns:
            List of ThreatAlert objects.
        """
        alerts = []

        # Filter for failed login attempts
        failed = df[
            (df["path"] == "/login") &
            (df["status"] == 401)
        ].copy()

        if failed.empty:
            return alerts

        failed = failed.set_index("timestamp")

        # Group by IP and resample by time window, count attempts
        attempts = failed.groupby("ip").resample(self.time_window).size()

        # Alert on IPs exceeding threshold
        suspicious = attempts[attempts > self.threshold]

        for (ip, time), count in suspicious.items():
            alerts.append(
                ThreatAlert(
                    ip=ip,
                    timestamp=time,
                    kind=self.kind,
                    count=int(count),
                    confidence=0.95  # High confidence for repeated 401s
                )
            )

        return alerts
