"""Rule-based detectors for Linux auth.log style events (SSH / sudo).

Uses parsed ``path`` / ``method`` only (not ``classification``), aligned with
``parse_auth_logs`` synthetic paths.
"""

from __future__ import annotations

from typing import List

import pandas as pd

from .base import BaseDetector, ThreatAlert

# Matches parser ``_auth_row`` path values for sshd / sudo outcomes
PATH_SSH_FAILED_PASSWORD = "ssh/failed_password"
PATH_SSH_INVALID_USER = "ssh/invalid_user"
PATH_SUDO_AUTH_FAILURE = "sudo/auth_failure"
METHOD_SSH = "SSH"
METHOD_SUDO = "SUDO"


def _burst_alerts_per_ip(
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


class AuthSshBruteforceDetector(BaseDetector):
    """Bursts of SSH failed password attempts from one source IP."""

    kind = "auth_ssh_bruteforce"
    description = "Bursts of sshd failed-password events (ssh/failed_password)"

    def __init__(self, threshold: int = 8, session_gap_seconds: int = 90):
        super().__init__(threshold)
        self.session_gap_seconds = session_gap_seconds

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        if df.empty or "path" not in df.columns or "method" not in df.columns:
            return []
        mask = (df["method"] == METHOD_SSH) & (df["path"] == PATH_SSH_FAILED_PASSWORD)
        return _burst_alerts_per_ip(
            df.loc[mask],
            kind=self.kind,
            threshold=self.threshold,
            session_gap_seconds=self.session_gap_seconds,
        )


class AuthSshUserEnumDetector(BaseDetector):
    """Bursts of SSH invalid username probes from one source IP."""

    kind = "auth_ssh_user_enum"
    description = "Bursts of sshd invalid-user events (ssh/invalid_user)"

    def __init__(self, threshold: int = 12, session_gap_seconds: int = 90):
        super().__init__(threshold)
        self.session_gap_seconds = session_gap_seconds

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        if df.empty or "path" not in df.columns or "method" not in df.columns:
            return []
        mask = (df["method"] == METHOD_SSH) & (df["path"] == PATH_SSH_INVALID_USER)
        return _burst_alerts_per_ip(
            df.loc[mask],
            kind=self.kind,
            threshold=self.threshold,
            session_gap_seconds=self.session_gap_seconds,
        )


class AuthSudoBruteforceDetector(BaseDetector):
    """Bursts of sudo PAM authentication failures (often local / same IP)."""

    kind = "auth_sudo_bruteforce"
    description = "Bursts of sudo pam_unix auth failures (sudo/auth_failure)"

    def __init__(self, threshold: int = 5, session_gap_seconds: int = 180):
        super().__init__(threshold)
        self.session_gap_seconds = session_gap_seconds

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        if df.empty or "path" not in df.columns or "method" not in df.columns:
            return []
        mask = (df["method"] == METHOD_SUDO) & (df["path"] == PATH_SUDO_AUTH_FAILURE)
        return _burst_alerts_per_ip(
            df.loc[mask],
            kind=self.kind,
            threshold=self.threshold,
            session_gap_seconds=self.session_gap_seconds,
        )
