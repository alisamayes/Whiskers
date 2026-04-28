"""Bursts of SSH failed password attempts from one source IP."""

from __future__ import annotations

from typing import List

import pandas as pd

from ..base import BaseDetector, ThreatAlert
from .auth_common import METHOD_SSH, PATH_SSH_FAILED_PASSWORD, burst_alerts_per_ip


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
        return burst_alerts_per_ip(
            df.loc[mask],
            kind=self.kind,
            threshold=self.threshold,
            session_gap_seconds=self.session_gap_seconds,
        )
