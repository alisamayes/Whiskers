"""Detector registry and selection helpers.

This keeps `whiskers.py` from manually importing/instantiating every detector and
lets the engine select detectors by enabled log families.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Sequence

from .access import (
    BruteForceDetector,
    CommandInjectionDetector,
    ExfiltrationDetector,
    FloodDetector,
    ScanDetector,
    SqlInjectionDetector,
)
from .auth import (
    AuthPrivilegeEscalationChain,
    AuthSshBruteforceDetector,
    AuthSshUserEnumDetector,
    AuthSudoBruteforceDetector,
)
from .base import BaseDetector
from .firewall import (
    FirewallEgressExfiltrationDetector,
    FirewallPortScanDetector,
    FirewallSshBruteforceDetector,
    FirewallSynFloodDetector,
)
from .ml_isolation import IsolationForestDetector
from .ml_supervised import SupervisedIPClassifierDetector


@dataclass(frozen=True)
class DetectorConfig:
    access_bruteforce_threshold: int = 10
    access_scan_threshold: int = 4
    access_flood_threshold: int = 100
    access_sql_injection_threshold: int = 2
    access_exfiltration_threshold: int = 2_000_000
    access_command_injection_threshold: int = 2

    auth_ssh_bruteforce_threshold: int = 8
    auth_ssh_user_enum_threshold: int = 12
    auth_sudo_bruteforce_threshold: int = 5

    auth_priv_escalation_threshold: int = 3
    auth_priv_escalation_window_seconds: int = 600
    auth_priv_escalation_first_fail_max_seconds: int = 240
    auth_priv_escalation_heuristic_threshold: int = 5

    firewall_port_scan_threshold: int = 10
    firewall_ssh_bruteforce_threshold: int = 25
    firewall_syn_flood_threshold_packets: int = 2000
    firewall_egress_exfil_threshold_bytes: int = 5_000_000


def build_default_detectors(cfg: DetectorConfig | None = None) -> List[BaseDetector]:
    """Instantiate the project’s default detector set."""
    cfg = cfg or DetectorConfig()
    return [
        # access
        BruteForceDetector(threshold=cfg.access_bruteforce_threshold),
        ScanDetector(threshold=cfg.access_scan_threshold),
        FloodDetector(threshold=cfg.access_flood_threshold),
        SqlInjectionDetector(threshold=cfg.access_sql_injection_threshold),
        ExfiltrationDetector(threshold=cfg.access_exfiltration_threshold),
        CommandInjectionDetector(threshold=cfg.access_command_injection_threshold),
        # auth
        AuthSshBruteforceDetector(
            threshold=cfg.auth_ssh_bruteforce_threshold, session_gap_seconds=90
        ),
        AuthSshUserEnumDetector(
            threshold=cfg.auth_ssh_user_enum_threshold, session_gap_seconds=90
        ),
        AuthSudoBruteforceDetector(
            threshold=cfg.auth_sudo_bruteforce_threshold, session_gap_seconds=180
        ),
        AuthPrivilegeEscalationChain(
            threshold=cfg.auth_priv_escalation_threshold,
            window_seconds=cfg.auth_priv_escalation_window_seconds,
            first_fail_max_seconds=cfg.auth_priv_escalation_first_fail_max_seconds,
            heuristic_threshold=cfg.auth_priv_escalation_heuristic_threshold,
        ),
        # firewall
        FirewallPortScanDetector(threshold=cfg.firewall_port_scan_threshold),
        FirewallSshBruteforceDetector(threshold=cfg.firewall_ssh_bruteforce_threshold),
        FirewallSynFloodDetector(threshold=cfg.firewall_syn_flood_threshold_packets),
        FirewallEgressExfiltrationDetector(
            threshold=cfg.firewall_egress_exfil_threshold_bytes
        ),
        # ML (always available)
        IsolationForestDetector(),
        SupervisedIPClassifierDetector(),
    ]


def select_detectors_for_sources(
    detectors: Sequence[BaseDetector], enabled_sources: Iterable[str]
) -> List[BaseDetector]:
    """Filter detectors by enabled log sources.

    - access detectors: kind starts with "access_"
    - auth detectors: kind starts with "auth_"
    - firewall detectors: kind starts with "firewall_"
    - ML detectors: always included (kind starts with "ml_" or equals "ml_anomaly")
    """
    enabled = {s.lower().strip() for s in enabled_sources if s}

    def keep(det: BaseDetector) -> bool:
        kind = getattr(det, "kind", "") or ""
        if kind.startswith("access_"):
            return "access" in enabled
        if kind.startswith("auth_"):
            return "auth" in enabled
        if kind.startswith("firewall_"):
            return "firewall" in enabled
        if kind.startswith("ml_") or kind == "ml_anomaly":
            return True
        # Default: keep (safer than dropping unknown kinds).
        return True

    return [d for d in detectors if keep(d)]
