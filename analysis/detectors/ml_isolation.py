"""Unsupervised anomaly detector using IsolationForest."""

from __future__ import annotations

from typing import List

import pandas as pd
from sklearn.ensemble import IsolationForest

from .base import BaseDetector, ThreatAlert
from analysis.feature_engineering import basic_aggregate_features


class IsolationForestDetector(BaseDetector):
    """Detect anomalous IPs using an IsolationForest over aggregate features."""

    kind = "ml_anomaly"
    description = "Unsupervised anomaly detector over per-IP aggregate features"

    def __init__(
        self,
        contamination: float = 0.1,
        n_estimators: int = 200,
        random_state: int | None = 42,
    ):
        # threshold is unused but kept for BaseDetector interface compatibility
        super().__init__(threshold=0)
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        alerts: List[ThreatAlert] = []

        if df.empty:
            return alerts

        # Build per-IP feature matrix
        features = basic_aggregate_features(df)
        if features.empty:
            return alerts

        # Fit IsolationForest on current data (online unsupervised mode)
        model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
        )
        model.fit(features)

        # Predict anomalies: -1 = anomaly, 1 = normal
        preds = model.predict(features)
        scores = model.decision_function(features)

        for ip, pred, score in zip(features.index, preds, scores):
            if pred == -1:
                alerts.append(
                    ThreatAlert(
                        ip=str(ip),
                        timestamp=None,
                        kind=self.kind,
                        count=1,
                        # Lower score -> more anomalous; map to 0–1 confidence roughly
                        confidence=float(max(0.0, min(1.0, -score))),
                    )
                )

        return alerts

