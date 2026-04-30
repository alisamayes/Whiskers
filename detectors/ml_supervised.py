"""Supervised IP-level classifier detector (normal vs threat)."""

from __future__ import annotations

import os
from typing import Any, List

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
        self.feature_columns: list[str] | None = None

        if os.path.exists(self.model_path):
            try:
                loaded = joblib.load(self.model_path)
                if isinstance(loaded, dict) and "model" in loaded:
                    self.model = loaded.get("model")
                    cols = loaded.get("feature_columns")
                    if isinstance(cols, list) and all(
                        isinstance(c, str) for c in cols
                    ):
                        self.feature_columns = cols
                else:
                    # Backward compatibility with older artifacts that saved model only.
                    self.model = loaded
            except Exception as e:
                print(f"Failed to load supervised model from {self.model_path}: {e}")
                self.model = None
        else:
            # Silent by default; detector will just return no alerts
            self.model = None

    def _align_features(self, features: pd.DataFrame) -> pd.DataFrame:
        if not self.feature_columns:
            return features
        aligned = features.copy()
        for col in self.feature_columns:
            if col not in aligned.columns:
                aligned[col] = 0.0
        return aligned[self.feature_columns]

    @staticmethod
    def _threat_probabilities(model: Any, features: pd.DataFrame) -> list[float] | None:
        if not hasattr(model, "predict_proba"):
            return None
        proba = model.predict_proba(features)
        classes = list(getattr(model, "classes_", []))
        if len(classes) >= 2:
            threat_index = classes.index(1) if 1 in classes else len(classes) - 1
            return [float(p[threat_index]) for p in proba]
        if len(classes) == 1:
            # One-class model: if class is threat-ish, confidence is 1.0; else 0.0.
            only = classes[0]
            val = 1.0 if only in (1, "1", "threat", "malicious") else 0.0
            return [val for _ in range(len(features))]
        return None

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        alerts: List[ThreatAlert] = []

        if self.model is None or df.empty:
            return alerts

        features = basic_aggregate_features(df)
        if features.empty:
            return alerts
        features = self._align_features(features)

        try:
            proba = self._threat_probabilities(self.model, features)
            if proba is not None:
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
        except Exception as e:
            print(f"Supervised detector inference skipped due to model/feature mismatch: {e}")

        return alerts
