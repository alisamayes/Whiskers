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
from parser.log_parser import parse_logs

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from analysis.feature_engineering import basic_aggregate_features


def main() -> None:
    log_path = "data/access.log"
    if not os.path.exists(log_path):
        print(f"{log_path} not found. Generate logs first with `python main.py -g`.")
        return

    # 1) Parse logs
    df = parse_logs(log_path, source="access")
    if df.empty:
        print("No log lines parsed. Aborting supervised training.")
        return

    # 2) Build per-IP features
    X = basic_aggregate_features(df)

    # 3) Build labels per IP: 1 if any attack classification seen for that IP
    # "normal" is the benign class; everything else is considered "threat"
    attack_ips = df[df["classification"] != "normal"]["ip"].unique()
    y = X.index.isin(attack_ips).astype(int)

    if y.sum() == 0:
        print("No malicious IPs found in this dataset; cannot train supervised model.")
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
    )
    clf.fit(X_train, y_train)

    # 6) Evaluate
    y_pred = clf.predict(X_test)
    print("Supervised IP classifier performance (0=normal, 1=threat):")
    print(classification_report(y_test, y_pred, digits=3))

    # 7) Save model
    os.makedirs("models", exist_ok=True)
    model_path = os.path.join("models", "ip_supervised_rf.joblib")
    joblib.dump(clf, model_path)
    print(f"Saved supervised IP classifier to {model_path}")


if __name__ == "__main__":
    main()
