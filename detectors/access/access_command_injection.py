from __future__ import annotations

from typing import List

import pandas as pd

from ..base import BaseDetector, ThreatAlert

SUSPECT_COMMAND_SUBSTRINGS = [
    ";",
    "&&",
    "||",
    "|",
    "$(",
    "`",
    "%3B",
    "%253B",
    "%7C",
    #   "%24%28",
    "%60",
    "echo+test",
    "probe_test",
    "exec_test",
    "test_exec",
    "cmd",
    "<cmd>",
    "<test>",
]

COMMAND_INJECTION_PATTERNS = [
    "/search?q=test;<simulated-command>",
    "/status?check=value&&<simulated-command>",
    "/search?q=test;<simulated-command>",
    "/debug?mode=$(<simulated-command>)",
    "/info?cmd=`<simulated-command>`",
    "/action?input=value|<simulated-command>",
    "/run?x=test%3B<simulated-command>",
    "/run?x=test%253B<simulated-command>",
    "/probe?id=<simulated-command>_delay_test",
    "/file?name=data;<simulated-command>",
    "/calculate?num=10;<simulated-command>",
    "/tools/exec/<simulated-command>_attempt",
    "/check?param=value;;;<simulated-command>",
    "/submit?value=$(echo+test)|<simulated-command>",
]


class CommandInjectionDetector(BaseDetector):
    """Detects likely command injection attempts based on request paths/query strings."""

    kind = "access_command_injection"
    description = (
        "Detects command injection-style payloads in request paths or query strings"
    )

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
        return any(token in lower for token in SUSPECT_COMMAND_SUBSTRINGS)

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        alerts: List[ThreatAlert] = []

        if df.empty or "path" not in df.columns:
            return alerts
        if "log_source" in df.columns:
            df = df[df["log_source"] == "access"]
            if df.empty:
                return alerts

        # This was for debuging purposes
        # df.to_pickle("data/dataframe.pkl")

        suspicious = df[df["path"].apply(self.is_suspicious)].copy()
        if suspicious.empty:
            return alerts

        suspicious = suspicious.sort_values(["ip", "timestamp"])
        gap = pd.Timedelta(seconds=self.session_gap_seconds)

        # Sessionise per IP: a command injection attack is a burst of suspicious paths
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
