"""
Unsupervised anomaly detector using IsolationForest.
The purpose of this detector is to identify potentially hostile IPs based purely on anomalous traffic patterns,
without relying on any classification labels. It analyzes aggregate features of traffic per IP and flags those 
that deviate significantly from normal behavior.
"""

from __future__ import annotations

import os
from typing import List

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .base import BaseDetector, ThreatAlert
from analysis.feature_engineering import basic_aggregate_features


class IsolationForestDetector(BaseDetector):
    """Detect anomalous IPs using an IsolationForest over aggregate features.

    This detector analyzes traffic patterns to identify potentially hostile IPs
    based purely on behavioral anomalies, without using any classification labels.
    """

    kind = "ml_anomaly"
    description = "Unsupervised anomaly detector over per-IP traffic patterns"

    def __init__(
        self,
        contamination: float = 0.1,
        n_estimators: int = 200,
        random_state: int | None = 42,
        model_path: str = "models/isolation_forest.joblib",
        scaler_path: str = "models/isolation_scaler.joblib",
    ):
        # threshold is unused but kept for BaseDetector interface compatibility
        super().__init__(threshold=0)
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.model = None
        self.scaler = None
        self._load_or_create_model()

    def _load_or_create_model(self):
        """Load existing model or prepare for training."""
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            try:
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                print(f"Loaded existing IsolationForest model from {self.model_path}")
            except Exception as e:
                print(f"Failed to load model: {e}. Will train new model.")
                self.model = None
                self.scaler = None
        else:
            print("No existing IsolationForest model found. Will train on first detection run.")

    def _save_model(self):
        """Save the trained model and scaler."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.scaler, self.scaler_path)
        print(f"Saved IsolationForest model to {self.model_path}")

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        alerts: List[ThreatAlert] = []

        if df.empty:
            return alerts

        # Build per-IP feature matrix (purely traffic-based, no classification)
        features = basic_aggregate_features(df)
        if features.empty:
            return alerts

        # Scale features for better anomaly detection
        if self.scaler is None:
            self.scaler = StandardScaler()
            features_scaled = self.scaler.fit_transform(features)
        else:
            features_scaled = self.scaler.transform(features)

        # Fit or update model
        if self.model is None:
            # Train new model
            self.model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=self.random_state,
            )
            self.model.fit(features_scaled)
            self._save_model()
            print(f"Trained new IsolationForest on {len(features)} IPs")
        else:
            # Use existing model (could add incremental learning here if needed)
            pass

        # Predict anomalies: -1 = anomaly (hostile), 1 = normal
        preds = self.model.predict(features_scaled)
        scores = self.model.decision_function(features_scaled)

        # Count classifications
        normal_count = sum(pred == 1 for pred in preds)
        hostile_count = sum(pred == -1 for pred in preds)
        total_ips = len(features)

        print(f"\n--- IsolationForest Anomaly Detection Results ---")
        print(f"Total unique IPs analyzed: {total_ips}")
        print(f"Classified as normal users: {normal_count} ({normal_count/total_ips*100:.1f}%)")
        print(f"Classified as hostile attackers: {hostile_count} ({hostile_count/total_ips*100:.1f}%)")
        print(".1f")
        print("--------------------------------------------------\n")

        # Generate alerts for hostile IPs
        for ip, pred, score in zip(features.index, preds, scores):
            if pred == -1:  # Hostile/anomalous
                alerts.append(
                    ThreatAlert(
                        ip=str(ip),
                        timestamp=None,
                        kind=self.kind,
                        count=1,
                        # Convert anomaly score to confidence (lower score = more anomalous)
                        confidence=float(max(0.0, min(1.0, (-score + 0.5) * 2))),  # Rough mapping
                    )
                )

        return alerts

