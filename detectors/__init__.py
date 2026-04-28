"""Threat detectors package.

Detectors are grouped by log family:
- `detectors.access.*`
- `detectors.auth.*`
- `detectors.firewall.*`
"""

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
from .base import BaseDetector, ThreatAlert
from .firewall import (
    FirewallEgressExfiltrationDetector,
    FirewallPortScanDetector,
    FirewallSshBruteforceDetector,
    FirewallSynFloodDetector,
)
from .ml_isolation import IsolationForestDetector
from .ml_supervised import SupervisedIPClassifierDetector

__all__ = [
    "BaseDetector",
    "ThreatAlert",
    # access
    "BruteForceDetector",
    "ScanDetector",
    "FloodDetector",
    "SqlInjectionDetector",
    "ExfiltrationDetector",
    "CommandInjectionDetector",
    # auth
    "AuthPrivilegeEscalationChain",
    "AuthSshBruteforceDetector",
    "AuthSshUserEnumDetector",
    "AuthSudoBruteforceDetector",
    # firewall
    "FirewallPortScanDetector",
    "FirewallSynFloodDetector",
    "FirewallSshBruteforceDetector",
    "FirewallEgressExfiltrationDetector",
    # ML
    "IsolationForestDetector",
    "SupervisedIPClassifierDetector",
]
