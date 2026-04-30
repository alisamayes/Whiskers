"""Train a simple supervised IP-level classifier (normal vs threat).

run with:
python -m analysis.train_supervised_ip_classifier

This script:
- Parses access logs from data/access.log
- Builds per-IP aggregate features
- Labels an IP as malicious if it ever generated a non-"normal" classification
- Trains a RandomForest classifier
- Saves the model to models/ip_supervised_rf.joblib
"""

from __future__ import annotations

import os
import platform

from parser.log_parser import parse_auth_logs, parse_firewall_logs, parse_logs

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from analysis.feature_engineering import basic_aggregate_features


def _load_training_dataframe() -> pd.DataFrame:
    """Load available labeled logs from access/auth/firewall sources."""
    sources = [
        ("data/access.log", "access", parse_logs),
        ("data/auth.log", "auth", parse_auth_logs),
        ("data/firewall.log", "firewall", parse_firewall_logs),
    ]
    frames: list[pd.DataFrame] = []
    for path, source_name, parser in sources:
        if not os.path.exists(path):
            continue
        df_src = parser(path, source=source_name)
        if not df_src.empty:
            frames.append(df_src)

    if not frames:
        return pd.DataFrame()
    df = pd.concat(frames, ignore_index=True)
    return df.sort_values("timestamp")


def main() -> None:
    # 1) Parse logs
    df = _load_training_dataframe()
    if df.empty:
        print("No parseable logs found. Generate logs first with `python main.py -g`.")
        return

    # 2) Build per-IP features
    X = basic_aggregate_features(df)

    # 3) Build labels per IP: 1 if any attack classification seen for that IP
    # "normal" is the benign class; everything else is considered "threat"
    attack_ips = df[df["classification"] != "normal"]["ip"].unique()
    y = X.index.isin(attack_ips).astype(int)

    positives = int(y.sum())
    negatives = int((y == 0).sum())
    if positives == 0 or negatives == 0:
        print(
            "Need both normal and malicious IPs to train supervised model. "
            f"Found normal={negatives}, malicious={positives}."
        )
        return
    min_class_count = int(min(positives, negatives))
    if min_class_count < 2:
        print(
            "Need at least 2 IP samples per class for stratified split. "
            f"Found smallest class size={min_class_count}."
        )
        return

    # 4) Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    # 5) Train a simple RandomForest
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)

    # 6) Evaluate
    y_pred = clf.predict(X_test)
    print("Supervised IP classifier performance (0=normal, 1=threat):")
    print(classification_report(y_test, y_pred, digits=3))

    # 7) Save model
    os.makedirs("models", exist_ok=True)
    model_path = os.path.join("models", "ip_supervised_rf.joblib")
    artifact = {
        "model": clf,
        "feature_columns": list(X.columns),
        "metadata": {
            "model_type": "RandomForestClassifier",
            "label_definition": "1 if IP has any non-normal classification",
            "sources_seen": sorted(df["log_source"].dropna().astype(str).unique().tolist()),
            "training_rows": int(len(df)),
            "training_unique_ips": int(len(X)),
            "sklearn_version": __import__("sklearn").__version__,
            "python_version": platform.python_version(),
        },
    }
    joblib.dump(artifact, model_path)
    print(f"Saved supervised IP classifier bundle to {model_path}")


if __name__ == "__main__":
    main()
