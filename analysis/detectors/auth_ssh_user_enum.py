"""Bursts of SSH invalid username probes from one source IP."""

from __future__ import annotations

from typing import List

import pandas as pd

from .auth_common import METHOD_SSH, PATH_SSH_INVALID_USER, burst_alerts_per_ip
from .base import BaseDetector, ThreatAlert


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
        return burst_alerts_per_ip(
            df.loc[mask],
            kind=self.kind,
            threshold=self.threshold,
            session_gap_seconds=self.session_gap_seconds,
        )
