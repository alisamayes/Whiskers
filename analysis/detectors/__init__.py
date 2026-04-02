"""Threat detectors package."""

from .base import BaseDetector, ThreatAlert
from .bruteforce import BruteForceDetector
from .scan import ScanDetector
from .flood import FloodDetector
from .sql_injection import SqlInjectionDetector
from .exfiltration import ExfiltrationDetector
from .command_injection import CommandInjectionDetector
from .auth_attacks import (
    AuthSshBruteforceDetector,
    AuthSshUserEnumDetector,
    AuthSudoBruteforceDetector,
)
from .ml_isolation import IsolationForestDetector
from .ml_supervised import SupervisedIPClassifierDetector

__all__ = [
    "BaseDetector",
    "ThreatAlert",
    "BruteForceDetector",
    "ScanDetector",
    "FloodDetector",
    "SqlInjectionDetector",
    "ExfiltrationDetector",
    "CommandInjectionDetector",
    "AuthSshBruteforceDetector",
    "AuthSshUserEnumDetector",
    "AuthSudoBruteforceDetector",
    "IsolationForestDetector",
    "SupervisedIPClassifierDetector",
]
