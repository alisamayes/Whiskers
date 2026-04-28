"""Directory scan/enumeration detector."""

from __future__ import annotations

from typing import List

import pandas as pd

from ..base import BaseDetector, ThreatAlert


class ScanDetector(BaseDetector):
    """Detects directory/path scanning attempts."""

    kind = "access_directory_scan"
    description = (
        "Detects probing for multiple paths (404 errors on different endpoints)"
    )

    def __init__(self, threshold: int = 4, session_gap_seconds: int = 10):
        """
        Initialize scan detector.

        Args:
            threshold: Number of unique 404 paths within a scan burst to alert.
            session_gap_seconds: Gap in seconds between 404s that starts a new burst.
        """
        super().__init__(threshold)
        self.session_gap_seconds = session_gap_seconds

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        """
        Detect directory scanning by looking for multiple 404 errors on different paths.

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

        # Filter for 404 responses (no use of classification/count)
        failed_requests = df[df["status"] == 404].copy()

        if failed_requests.empty:
            return alerts

        failed_requests = failed_requests.sort_values(["ip", "timestamp"])
        gap = pd.Timedelta(seconds=self.session_gap_seconds)

        # Sessionise per IP: a scan is a sequence of 404s with small gaps
        for ip, group in failed_requests.groupby("ip"):
            group = group.sort_values("timestamp")
            session_start_idx = 0

            for i in range(1, len(group)):
                prev_ts = group.iloc[i - 1]["timestamp"]
                cur_ts = group.iloc[i]["timestamp"]

                if cur_ts - prev_ts > gap:
                    session = group.iloc[session_start_idx:i]
                    unique_paths = session["path"].nunique()
                    if unique_paths >= self.threshold:
                        alerts.append(
                            ThreatAlert(
                                ip=ip,
                                timestamp=session["timestamp"].max(),
                                kind=self.kind,
                                count=int(unique_paths),
                                confidence=0.85,
                            )
                        )
                    session_start_idx = i

            # Final session for this IP
            session = group.iloc[session_start_idx:]
            unique_paths = session["path"].nunique()
            if unique_paths >= self.threshold:
                alerts.append(
                    ThreatAlert(
                        ip=ip,
                        timestamp=session["timestamp"].max(),
                        kind=self.kind,
                        count=int(unique_paths),
                        confidence=0.85,
                    )
                )

        return alerts
