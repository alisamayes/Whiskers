"""Threat detectors package."""

from .auth_attacks import (
    AuthPrivilegeEscalationChain,
    AuthSshBruteforceDetector,
    AuthSshUserEnumDetector,
    AuthSudoBruteforceDetector,
)
from .base import BaseDetector, ThreatAlert
from .bruteforce import BruteForceDetector
from .command_injection import CommandInjectionDetector
from .exfiltration import ExfiltrationDetector
from .flood import FloodDetector
from .ml_isolation import IsolationForestDetector
from .ml_supervised import SupervisedIPClassifierDetector
from .scan import ScanDetector
from .sql_injection import SqlInjectionDetector

__all__ = [
    "BaseDetector",
    "ThreatAlert",
    "BruteForceDetector",
    "ScanDetector",
    "FloodDetector",
    "SqlInjectionDetector",
    "ExfiltrationDetector",
    "CommandInjectionDetector",
    "AuthPrivilegeEscalationChain",
    "AuthSshBruteforceDetector",
    "AuthSshUserEnumDetector",
    "AuthSudoBruteforceDetector",
    "IsolationForestDetector",
    "SupervisedIPClassifierDetector",
]
