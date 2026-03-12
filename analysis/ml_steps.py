"""Small, step-by-step helper functions for building an ML model.

This module is deliberately simple: each function corresponds to one
step in the pipeline.  The goal is educational rather than production
quality – we'll build the pieces together with the user.

Typical usage pattern in a Python REPL or notebook:

    from analysis import ml_steps
    df = ml_steps.load_logs("data/access.log")
    features = ml_steps.compute_features(df)
    labels = ml_steps.label_ips(df)
    X, y = ml_steps.prepare_dataset(features, labels)
    model, metrics = ml_steps.train_model(X, y)

"""

from __future__ import annotations

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import train_test_split

from parser.log_parser import parse_logs
from analysis import feature_engineering


def load_logs(path: str) -> pd.DataFrame:
    """Parse a log file and return a DataFrame.

    Parameters
    ----------
    path : str
        Path to an access log (the same one you use elsewhere).

    Returns
    -------
    pd.DataFrame
        Parsed log entries with at least the columns ``ip`` and ``path``.
    """
    print(f"Loading logs from {path}...")
    df = parse_logs(path, source="ml")
    print(f"Loaded {len(df)} rows")
    return df


def compute_features(df: pd.DataFrame) -> pd.DataFrame:
    """Convert raw log rows into per-IP aggregated features.

    This just calls the existing ``basic_aggregate_features`` helper and
    prints the result so you can inspect it.
    """
    print("Computing features from dataframe...")
    features = feature_engineering.basic_aggregate_features(df)
    print(f"Computed features for {len(features)} unique IPs")
    print(features.head())
    return features


def compute_request_features(df: pd.DataFrame) -> pd.DataFrame:
    """Convert each log row into individual features for per-request classification.

    Instead of aggregating by IP, this creates one row per log entry.
    Useful for classifying individual requests as safe/threat.
    """
    print("Computing per-request features...")
    
    # start with the raw log data
    features = df.copy()
    
    # add some request-level features
    features['is_post'] = (features['method'] == 'POST').astype(int)
    features['is_error'] = (features['status'] >= 400).astype(int)
    features['is_5xx'] = (features['status'] >= 500).astype(int)
    features['path_length'] = features['path'].str.len()
    features['has_sql_keywords'] = features['path'].str.contains(
        r"'|union|select|drop|insert|update", case=False, na=False
    ).astype(int)
    features['has_admin_path'] = features['path'].str.contains(
        r'/admin|wp-admin|\.env|\.git|phpmyadmin', case=False, na=False
    ).astype(int)
    features['bytes_log'] = np.log1p(features['bytes_sent'])  # log transform
    
    # keep only numeric features for now
    numeric_cols = ['status', 'bytes_sent', 'bytes_log', 'path_length', 
                   'is_post', 'is_error', 'is_5xx', 'has_sql_keywords', 'has_admin_path']
    
    result = features[numeric_cols].copy()
    print(f"Computed features for {len(result)} individual requests")
    print(result.head())
    return result


def label_ips(df: pd.DataFrame) -> dict[str, str]:
    """Create a label map from IP address to attack type.

    When training on synthetic data produced by ``simulator/log_simulator.py``
    the parser already keeps a ``classification`` column containing the
    attack name (or ``"normal"`` for benign rows).  We simply take the
    most common classification for each IP.

    This function still works with real-world logs where you don't have a
    known attack tag: the previous heuristic based on error rate is used
    as a fallback.
    """
    print("Generating labels (based on classification column)...")
    labels: dict[str, str] = {}

    for ip, group in df.groupby("ip"):
        # if the simulator tagged the rows, use the most frequent tag
        if "classification" in group.columns:
            mode = group["classification"].mode()
            if len(mode) > 0 and mode.iloc[0] != "normal":
                labels[ip] = mode.iloc[0]
                continue
        # fallback heuristic: >50% errors -> brute force
        total = len(group)
        errors = (group["status"] >= 400).sum()
        if total > 0 and errors / total > 0.5:
            labels[ip] = "brute_force"
        else:
            labels[ip] = "normal"

    print(f"Labeled {len(labels)} IPs")
    return labels


def prepare_dataset(features: pd.DataFrame, labels: dict[str, str]):
    """Turn features+label map into training arrays.

    Returns
    -------
    X : pd.DataFrame
        Feature dataframe aligned with labels
    y : pd.Series
        Corresponding labels
    """
    print("Preparing dataset for modeling...")
    # align index
    y = features.index.to_series().map(lambda ip: labels.get(ip, "normal"))
    X = features.copy()
    print("Class distribution:")
    print(y.value_counts())
    return X, y


def train_model(X: pd.DataFrame, y: pd.Series):
    """Train a simple random forest and return metrics.

    This function performs a train/test split and prints a
    classification report so you can see how the model is doing.
    """
    print("Training model...")
    
    # filter out classes with too few samples for stratification
    class_counts = y.value_counts()
    valid_classes = class_counts[class_counts >= 2].index
    mask = y.isin(valid_classes)
    X_filtered = X[mask]
    y_filtered = y[mask]
    
    if len(y_filtered) < len(y):
        print(f"Filtered out {len(y) - len(y_filtered)} samples from rare classes")
        print(f"Remaining: {len(y_filtered)} samples")
    
    # use stratification only if we have enough samples per class
    stratify_param = y_filtered if y_filtered.value_counts().min() >= 2 else None
    
    X_train, X_test, y_train, y_test = train_test_split(
        X_filtered, y_filtered, test_size=0.2, random_state=42, stratify=stratify_param
    )
    
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))
    return model, {"accuracy": accuracy_score(y_test, y_pred)}


def generate_logs(size: int = 2000) -> pd.DataFrame:
    """Convenience wrapper around the simulator.

    Produces ``size`` base log entries (attacks added probabilistically)
    and returns the resulting DataFrame.

    The generated log file is written to ``data/access.log`` just like the
    rest of the application, then parsed into a DataFrame so you can
    immediately feed it to the other helpers.
    """
    from simulator.log_simulator import generate_logs as _gen

    print(f"Generating {size} log lines via simulator...")
    _gen(size)
    return load_logs("data/access.log")


if __name__ == "__main__":
    print("This module provides helper steps for building an ML model.")
    print("Import and call the functions interactively.")
