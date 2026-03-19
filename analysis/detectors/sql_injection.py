"""SQL injection / query tampering detector."""

from __future__ import annotations

from typing import List
import pandas as pd
from .base import BaseDetector, ThreatAlert


SUSPECT_SUBSTRINGS = [
    " or 1=1",
    " or \"1\"=\"1",
    "'--",
    " union select ",
    " drop table ",
    "../",
    "%2e%2e%2f",
    ";--",
]

SQLI_PATTERNS = [
    "/search?q=' OR 1=1 --",
    "/search?q=\" OR \"1\"=\"1",
    "/login?user=admin'--",
    "/products?id=1 UNION SELECT username, password FROM users",
    "/items?id=1; DROP TABLE users",
]


class SqlInjectionDetector(BaseDetector):
    """Detects likely SQL injection attempts based on request paths/query strings."""

    kind = "sql_injection"
    description = "Detects SQLi-style payloads in request paths or query strings"

    def __init__(self, threshold: int = 3, session_gap_seconds: int = 60):
        """
        Args:
            threshold: Number of suspicious requests per IP within a burst to alert.
            session_gap_seconds: Gap in seconds between suspicious requests that starts a new burst.
        """
        super().__init__(threshold)
        self.session_gap_seconds = session_gap_seconds

    def is_suspicious(self, path: str) -> bool:
        lower = path.lower()
        return any(token in lower for token in SUSPECT_SUBSTRINGS)

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        alerts: List[ThreatAlert] = []

        if df.empty or "path" not in df.columns:
            return alerts

        suspicious = df[df["path"].apply(self.is_suspicious)].copy()
        if suspicious.empty:
            return alerts

        suspicious = suspicious.sort_values(["ip", "timestamp"])
        gap = pd.Timedelta(seconds=self.session_gap_seconds)

        # Sessionise per IP: a SQLi attack is a burst of suspicious paths
        for ip, group in suspicious.groupby("ip"):
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
                                confidence=0.9,
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
                        confidence=0.9,
                    )
                )

        return alerts

