"""Bursts of sudo PAM authentication failures (often local / same IP)."""

from __future__ import annotations

from typing import List

import pandas as pd

from ..base import BaseDetector, ThreatAlert
from .auth_common import METHOD_SUDO, PATH_SUDO_AUTH_FAILURE, burst_alerts_per_ip


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
        return burst_alerts_per_ip(
            df.loc[mask],
            kind=self.kind,
            threshold=self.threshold,
            session_gap_seconds=self.session_gap_seconds,
        )
