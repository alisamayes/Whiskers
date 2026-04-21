"""SSH login success followed by sudo auth failures for the same account."""

from __future__ import annotations

from typing import List

import pandas as pd

from .auth_common import METHOD_SSH, PATH_SSH_ACCEPTED, PATH_SUDO_AUTH_FAILURE
from .base import BaseDetector, ThreatAlert


class AuthPrivilegeEscalationChain(BaseDetector):
    """SSH login success followed by sudo auth failures for the same account.

    When the dataframe has Whiskers-style ``classification`` / ``count`` labels
    (simulated logs), only anchors on ``ssh/accepted`` rows tagged
    ``auth_privilege_escalation`` and matches sudo failures with the same episode
    ``count``. Unlabeled logs use a strict time-based heuristic only.
    """

    kind = "auth_privilege_escalation"
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

    def alerts_for_accepts(
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
            return self.alerts_for_accepts(
                work,
                priv_accepts,
                match_episode_count=True,
                min_failures=self.threshold,
            )

        return self.alerts_for_accepts(
            work,
            accepts,
            match_episode_count=False,
            min_failures=self.heuristic_threshold,
        )
