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
PATH_SSH_ACCEPTED = "ssh/accepted"
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


class AuthPrivescChainDetector(BaseDetector):
    """SSH login success followed by sudo auth failures for the same account.

    When the dataframe has Whiskers-style ``classification`` / ``count`` labels
    (simulated logs), only anchors on ``ssh/accepted`` rows tagged
    ``auth_privesc_chain`` and matches sudo failures with the same episode
    ``count``. Unlabeled logs use a strict time-based heuristic only.
    """

    kind = "auth_privesc_chain"
    description = "SSH accepted then sudo pam failures (labeled episode or heuristic)"

    def __init__(
        self,
        threshold: int = 3,
        window_seconds: int = 600,
        first_fail_max_seconds: int = 240,
        heuristic_threshold: int = 5,
    ):
        super().__init__(threshold)
        self.window_seconds = window_seconds
        self.first_fail_max_seconds = first_fail_max_seconds
        self.heuristic_threshold = heuristic_threshold

    def _alerts_for_accepts(
        self,
        work: pd.DataFrame,
        accept_rows: pd.DataFrame,
        *,
        match_episode_count: bool,
        min_failures: int,
    ) -> List[ThreatAlert]:
        alerts: List[ThreatAlert] = []
        window = pd.Timedelta(seconds=self.window_seconds)
        grace = pd.Timedelta(seconds=self.first_fail_max_seconds)
        for _, row in accept_rows.iterrows():
            user = row["auth_user"]
            if user is None or pd.isna(user):
                continue
            t0 = row["timestamp"]
            t1 = t0 + window
            ip = row["ip"]
            mask = (
                (work["timestamp"] >= t0)
                & (work["timestamp"] <= t1)
                & (work["path"] == PATH_SUDO_AUTH_FAILURE)
                & (work["auth_user"] == user)
            )
            if match_episode_count and "count" in work.columns:
                mask &= work["count"] == row["count"]
            fails = work.loc[mask]
            n_fail = len(fails)
            if n_fail < min_failures:
                continue
            first_fail = fails["timestamp"].min()
            if first_fail > t0 + grace:
                continue
            alerts.append(
                ThreatAlert(
                    ip=str(ip),
                    timestamp=fails["timestamp"].max(),
                    kind=self.kind,
                    count=n_fail,
                    confidence=0.9 if match_episode_count else 0.75,
                )
            )
        return alerts

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        if (
            df.empty
            or "path" not in df.columns
            or "method" not in df.columns
            or "auth_user" not in df.columns
            or "timestamp" not in df.columns
            or "ip" not in df.columns
        ):
            return []

        work = df.sort_values("timestamp")
        accepts = work[
            (work["method"] == METHOD_SSH) & (work["path"] == PATH_SSH_ACCEPTED)
        ]
        if accepts.empty:
            return []

        labeled = (
            "classification" in work.columns
            and (work["classification"] == self.kind).any()
        )
        if labeled:
            priv_accepts = accepts[accepts["classification"] == self.kind]
            if priv_accepts.empty:
                return []
            return self._alerts_for_accepts(
                work,
                priv_accepts,
                match_episode_count=True,
                min_failures=self.threshold,
            )

        return self._alerts_for_accepts(
            work,
            accepts,
            match_episode_count=False,
            min_failures=self.heuristic_threshold,
        )
