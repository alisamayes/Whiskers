"""Supervised IP-level classifier detector (normal vs threat)."""

from __future__ import annotations

import os
from typing import List

import joblib
import pandas as pd

from analysis.feature_engineering import basic_aggregate_features

from .base import BaseDetector, ThreatAlert


class SupervisedIPClassifierDetector(BaseDetector):
    """Uses a pre-trained supervised model to classify IPs as normal vs threat."""

    kind = "ml_supervised"
    description = "Supervised IP-level classifier (0=normal, 1=threat)"

    def __init__(
        self,
        model_path: str = "models/ip_supervised_rf.joblib",
        threshold: float = 0.5,
    ):
        super().__init__(threshold=0)
        self.model_path = model_path
        self.score_threshold = threshold
        self.model = None

        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
            except Exception as e:
                print(f"Failed to load supervised model from {self.model_path}: {e}")
                self.model = None
        else:
            # Silent by default; detector will just return no alerts
            self.model = None

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        alerts: List[ThreatAlert] = []

        if self.model is None or df.empty:
            return alerts

        features = basic_aggregate_features(df)
        if features.empty:
            return alerts

        # Get probability of class 1 (threat), if available
        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(features)[:, 1]
            for ip, p in zip(features.index, proba):
                if p >= self.score_threshold:
                    alerts.append(
                        ThreatAlert(
                            ip=str(ip),
                            timestamp=None,
                            kind=self.kind,
                            count=1,
                            confidence=float(p),
                        )
                    )
        else:
            # Fallback: use hard predictions only
            preds = self.model.predict(features)
            for ip, pred in zip(features.index, preds):
                if int(pred) == 1:
                    alerts.append(
                        ThreatAlert(
                            ip=str(ip),
                            timestamp=None,
                            kind=self.kind,
                            count=1,
                            confidence=0.8,
                        )
                    )

        return alerts
