"""Base detector class and data structures for threat alerts."""

from __future__ import annotations

from dataclasses import dataclass
from abc import ABC, abstractmethod
from typing import List
import pandas as pd


@dataclass
class ThreatAlert:
    """Represents a single threat detection."""
    ip: str
    timestamp: pd.Timestamp | None
    kind: str
    count: int
    confidence: float = 0.8

    def __repr__(self) -> str:
        if self.timestamp:
            return f"ThreatAlert({self.kind}, ip={self.ip}, time={self.timestamp}, count={self.count})"
        return f"ThreatAlert({self.kind}, ip={self.ip}, count={self.count})"


class BaseDetector(ABC):
    """Abstract base class for all threat detectors."""

    kind: str = "unknown"
    description: str = ""

    def __init__(self, threshold: int = 10):
        """
        Initialize detector with a configurable threshold.
        
        Args:
            threshold: The alert threshold for this detector.
        """
        self.threshold = threshold

    @abstractmethod
    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        """
        Run threat detection on the given log dataframe.
        
        Args:
            df: Parsed access log dataframe with columns: ip, timestamp, path, status, etc.
            
        Returns:
            List of ThreatAlert objects for detected threats.
        """
        pass
