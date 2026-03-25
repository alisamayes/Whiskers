"""
Unsupervised anomaly detector using IsolationForest.

Scores each IP from aggregate *behaviour* (traffic shape only — no classification
labels). An IP is flagged as a hostile candidate when it is both a multivariate
outlier (IF) and shows attack-like behaviour (scanning, errors, burst rate, etc.).
"""

from __future__ import annotations

from typing import List

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .base import BaseDetector, ThreatAlert
from analysis.feature_engineering import basic_aggregate_features


def _robust_left_tail_threshold(scores: np.ndarray, mad_multiplier: float) -> float:
    """Threshold on sklearn IF score_samples: lower = more anomalous.

    Uses median minus mad_multiplier * robust sigma (MAD-based). Fewer false
    positives than forcing a fixed contamination fraction of the population.
    """
    scores = np.asarray(scores, dtype=float)
    med = float(np.median(scores))
    mad = float(np.median(np.abs(scores - med)))
    sigma = 1.4826 * mad if mad > 1e-12 else float(np.std(scores))
    if sigma < 1e-12:
        return med
    return med - mad_multiplier * sigma


def _behavior_enriched_features(df: pd.DataFrame, features: pd.DataFrame) -> pd.DataFrame:
    """Add behaviour-only columns (no log classification labels)."""
    out = features.copy()
    tr = out["total_requests"].clip(lower=1)
    out["path_scan_ratio"] = (out["unique_paths"] / tr).clip(0.0, 1.0)

    ts = df["timestamp"]
    if ts.dtype == "O":
        ts = pd.to_datetime(ts)
    tg = df.assign(_ts=ts).groupby("ip")["_ts"]
    span = (tg.max() - tg.min()).dt.total_seconds()
    span = span.reindex(out.index).fillna(0.0) + 1e-3  # seconds; avoid div0
    out["requests_per_minute"] = out["total_requests"] / (span / 60.0)

    # Fast / automated traffic: very small mean gap between requests
    ai = out["avg_interval"].replace(0.0, np.nan).fillna(1e6)
    out["burstiness"] = 1.0 / (1.0 + ai)  # higher when intervals are short

    if "method" in df.columns:
        is_post = (df["method"].astype(str).str.upper() == "POST").groupby(df["ip"]).mean()
        out["post_fraction"] = is_post.reindex(out.index).fillna(0.0)
    else:
        out["post_fraction"] = 0.0

    return out.replace([np.inf, -np.inf], np.nan).fillna(0.0)


def _behavioral_risk(feat: pd.DataFrame) -> pd.ndarray:
    """Average percentile rank of attack-shaped signals (0–1), batch-relative."""

    def pct(col: str) -> pd.Series:
        s = feat[col]
        if s.nunique() <= 1:
            return pd.Series(0.5, index=s.index)
        return s.rank(pct=True)

    parts = [
        pct("path_scan_ratio"),
        pct("error_rate"),
        pct("fraction_4xx"),
        pct("requests_per_minute"),
        pct("burstiness"),
    ]
    if "post_fraction" in feat.columns:
        parts.append(pct("post_fraction"))
    return np.mean([p.values for p in parts], axis=0)


class IsolationForestDetector(BaseDetector):
    """IsolationForest over per-IP behaviour; alerts combine IF scores + behaviour gate."""

    kind = "ml_anomaly"
    description = "Unsupervised anomaly detector over per-IP traffic patterns"

    def __init__(
        self,
        threshold: int = 0,
        n_estimators: int = 200,
        random_state: int | None = 42,
        mad_multiplier: float = 2.5,
        min_behavioral_risk: float = 0.55,
        severe_behavioral_risk: float = 0.82,
        min_ips_for_forest: int = 6,
        # sklearn needs contamination for training; kept small — alert threshold is MAD-based
        forest_contamination: float = 0.02,
    ):
        super().__init__(threshold=threshold)
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.mad_multiplier = mad_multiplier
        self.min_behavioral_risk = min_behavioral_risk
        self.severe_behavioral_risk = severe_behavioral_risk
        self.min_ips_for_forest = min_ips_for_forest
        self.forest_contamination = forest_contamination

    def detect(self, df: pd.DataFrame) -> List[ThreatAlert]:
        alerts: List[ThreatAlert] = []
        if df.empty:
            return alerts

        features = basic_aggregate_features(df)
        if features.empty:
            return alerts

        features = _behavior_enriched_features(df, features)
        feature_cols = features.select_dtypes(include=[np.number]).columns.tolist()
        X_df = features[feature_cols]
        ips = features.index.to_list()
        n = len(features)

        risk = _behavioral_risk(features)

        scaler = StandardScaler()
        X = scaler.fit_transform(X_df.values)

        use_forest = n >= self.min_ips_for_forest
        if use_forest:
            max_samples = min(256, max(2, n))
            contamination = float(np.clip(self.forest_contamination, 0.001, 0.5))
            model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=contamination,
                random_state=self.random_state,
                max_samples=max_samples,
            )
            model.fit(X)
            scores = model.score_samples(X)
            cutoff = _robust_left_tail_threshold(scores, self.mad_multiplier)
            if_outlier = scores < cutoff
        else:
            scores = np.zeros(n)
            cutoff = float("nan")
            if_outlier = np.zeros(n, dtype=bool)

        for i, ip in enumerate(ips):
            r = float(risk[i])
            hostile = (
                use_forest
                and if_outlier[i]
                and r >= self.min_behavioral_risk
            ) or (r >= self.severe_behavioral_risk)

            if not hostile:
                continue

            if use_forest and scores[i] < cutoff:
                depth = float((cutoff - scores[i]) / (abs(cutoff) + 1e-6))
                conf = float(np.clip(0.35 + 0.4 * min(1.0, depth) + 0.25 * r, 0.0, 1.0))
            else:
                conf = float(np.clip(0.5 + 0.5 * r, 0.0, 1.0))

            alerts.append(
                ThreatAlert(
                    ip=str(ip),
                    timestamp=None,
                    kind=self.kind,
                    count=1,
                    confidence=conf,
                )
            )

        print("\n--- Behaviour anomaly detector ---")
        print(f"Unique IPs in this log: {n}")
        if use_forest:
            print(f"Outlier sensitivity: {self.mad_multiplier:g}× ")
        else:
            print(f" Only {n} IPs here — not enough for the full model. Only IPs with very extreme attack-like behaviour were considered.")
        print(
            f"Flagged as possible hostile IPs: {len(alerts)} "
            f"(out of {n} unique addresses)"
        )
        print("--------------------------------------------------------\n")

        return alerts
