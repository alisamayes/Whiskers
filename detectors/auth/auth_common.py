"""Shared paths and burst helpers for auth.log-style detectors.

Aligned with ``parser.log_parser`` synthetic ``path`` / ``method`` values.
"""

from __future__ import annotations

from typing import List

import pandas as pd

from ..base import ThreatAlert

PATH_SSH_FAILED_PASSWORD = "ssh/failed_password"
PATH_SSH_INVALID_USER = "ssh/invalid_user"
PATH_SSH_ACCEPTED = "ssh/accepted"
PATH_SUDO_AUTH_FAILURE = "sudo/auth_failure"
METHOD_SSH = "SSH"
METHOD_SUDO = "SUDO"


def burst_alerts_per_ip(
    subset: pd.DataFrame,
    *,
    kind: str,
    threshold: int,
    session_gap_seconds: int,
    confidence: float = 0.92,
) -> List[ThreatAlert]:
    """One alert per IP burst where consecutive rows are within ``session_gap_seconds``."""
    alerts: List[ThreatAlert] = []
    if subset.empty or "ip" not in subset.columns or "timestamp" not in subset.columns:
        return alerts

    work = subset.sort_values(["ip", "timestamp"])
    gap = pd.Timedelta(seconds=session_gap_seconds)

    for ip, group in work.groupby("ip"):
        group = group.sort_values("timestamp")
        start = 0
        for i in range(1, len(group)):
            if group.iloc[i]["timestamp"] - group.iloc[i - 1]["timestamp"] > gap:
                seg = group.iloc[start:i]
                if len(seg) >= threshold:
                    alerts.append(
                        ThreatAlert(
                            ip=str(ip),
                            timestamp=seg["timestamp"].max(),
                            kind=kind,
                            count=len(seg),
                            confidence=confidence,
                        )
                    )
                start = i
        seg = group.iloc[start:]
        if len(seg) >= threshold:
            alerts.append(
                ThreatAlert(
                    ip=str(ip),
                    timestamp=seg["timestamp"].max(),
                    kind=kind,
                    count=len(seg),
                    confidence=confidence,
                )
            )
    return alerts
