"""Directory scan/enumeration detector."""

from __future__ import annotations

from typing import List
import pandas as pd
from .base import BaseDetector, ThreatAlert


class ScanDetector(BaseDetector):
    """Detects directory/path scanning attempts."""

    kind = "directory_scan"
    description = "Detects probing for multiple paths (404 errors on different endpoints)"

    def __init__(self, threshold: int = 4, time_window: str = "30s"):
        """
        Initialize scan detector.
        
        Args:
            threshold: Number of unique 404 paths per time window to alert.
            time_window: Pandas time window string (e.g., '30s', '1min').
        """
        super().__init__(threshold)
        self.time_window = time_window

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        """
        Detect directory scanning by looking for multiple 404 errors on different paths.
        
        Args:
            df: Parsed access log dataframe.
            
        Returns:
            List of ThreatAlert objects.
        """
        alerts = []

        # Filter for 404 responses
        failed_requests = df[df["status"] == 404].copy()

        if failed_requests.empty:
            return alerts

        failed_requests = failed_requests.set_index("timestamp")

        # Group by IP and resample, count unique paths with 404
        path_counts = failed_requests.groupby("ip").resample(self.time_window)["path"].nunique()

        # Alert on IPs with many unique failed paths
        suspicious = path_counts[path_counts > self.threshold]

        for (ip, time), count in suspicious.items():
            alerts.append(
                ThreatAlert(
                    ip=ip,
                    timestamp=time,
                    kind=self.kind,
                    count=int(count),
                    confidence=0.85  # Good confidence but some false positives possible
                )
            )

        return alerts
