"""Request flood/DoS detector."""

from __future__ import annotations

from typing import List
import pandas as pd
from .base import BaseDetector, ThreatAlert


class FloodDetector(BaseDetector):
    """Detects request flood (DoS) attacks."""

    kind = "request_flood"
    description = "Detects unusual request spike patterns (high request rate)"

    def __init__(self, threshold: int = 100, time_window: str = "60s", min_gap: int = 60):
        """
        Initialize flood detector.
        
        Args:
            threshold: Number of requests per time window to alert.
            time_window: Pandas time window string (e.g., '60s', '1min').
            min_gap: Minimum seconds between separate alerts for same IP.
        """
        super().__init__(threshold)
        self.time_window = time_window
        self.min_gap = min_gap

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        """
        Detect request floods by looking for high request rates per IP.
        
        Args:
            df: Parsed access log dataframe.
            
        Returns:
            List of ThreatAlert objects.
        """
        alerts = []

        if df.empty:
            return alerts

        df = df.sort_values("timestamp").copy()
        df = df.set_index("timestamp")

        # Group by IP and find rolling request counts
        for ip, group in df.groupby("ip"):
            rolling_counts = group["path"].rolling(self.time_window).count()

            # Find times where count exceeds threshold
            flood_points = rolling_counts[rolling_counts > self.threshold]

            if flood_points.empty:
                continue

            # De-duplicate: only alert once per min_gap seconds per IP
            last_alert_time = None

            for time, count in flood_points.items():
                if last_alert_time is None or (time - last_alert_time).total_seconds() > self.min_gap:
                    alerts.append(
                        ThreatAlert(
                            ip=ip,
                            timestamp=time,
                            kind=self.kind,
                            count=int(count),
                            confidence=0.90  # Very high confidence for rate anomalies
                        )
                    )
                    last_alert_time = time

        return alerts
