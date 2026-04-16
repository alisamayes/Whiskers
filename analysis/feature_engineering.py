from __future__ import annotations

import pandas as pd


def basic_aggregate_features(df: pd.DataFrame) -> pd.DataFrame:
    """Return a feature frame aggregated by IP address.

    The returned DataFrame has one row per unique IP and at least the
    following columns:

    * ``total_requests`` - total number of log rows for that IP
    * ``unique_paths`` - count of distinct ``path`` values
    * ``error_rate`` - fraction of requests with HTTP status >= 400
    * ``avg_interval`` - mean time between consecutive requests (seconds)

    Additional features can be added over time.  This is a starting point
    for a feature matrix that could be fed to an anomaly detector or
    classifier later.
    """

    # make sure timestamp is datetime
    df = df.copy()
    if df["timestamp"].dtype == "O":
        df["timestamp"] = pd.to_datetime(df["timestamp"])

    grouped = df.groupby("ip")

    # base frame indexed by IP
    features = pd.DataFrame(index=grouped.size().index)
    features["total_requests"] = grouped.size()
    features["unique_paths"] = grouped["path"].nunique()

    # compute status-based fractions without DataFrameGroupBy.apply
    status = df["status"]
    by_ip = df["ip"]

    error_flag = status >= 400
    features["error_rate"] = error_flag.groupby(by_ip).mean()

    frac_2xx = status.between(200, 299)
    frac_4xx = status.between(400, 499)
    frac_5xx = status >= 500

    features["fraction_2xx"] = frac_2xx.groupby(by_ip).mean()
    features["fraction_4xx"] = frac_4xx.groupby(by_ip).mean()
    features["fraction_5xx"] = frac_5xx.groupby(by_ip).mean()

    # bytes_sent aggregates (if present)
    if "bytes_sent" in df.columns:
        features["total_bytes"] = grouped["bytes_sent"].sum()
        features["avg_bytes"] = grouped["bytes_sent"].mean()

    # user-agent diversity
    if "agent" in df.columns:
        features["unique_user_agents"] = grouped["agent"].nunique()

    # compute avg interval
    def avg_interval(series: pd.Series) -> float:
        if len(series) < 2:
            return 0.0
        diffs = series.sort_values().diff().dt.total_seconds().dropna()
        return diffs.mean()

    timestamp_series = grouped["timestamp"].apply(list)
    features["avg_interval"] = timestamp_series.apply(
        lambda lst: avg_interval(pd.Series(lst))
    )

    return features


# placeholder for more sophisticated feature builders, e.g. rolling
# statistics, user-agent entropy, etc.


if __name__ == "__main__":
    # quick sanity check
    import pandas as pd

    df = pd.DataFrame(
        [
            {
                "ip": "1.1.1.1",
                "timestamp": pd.Timestamp("2026-03-10 00:00"),
                "path": "/",
                "status": 200,
            },
            {
                "ip": "1.1.1.1",
                "timestamp": pd.Timestamp("2026-03-10 00:00:05"),
                "path": "/login",
                "status": 401,
            },
            {
                "ip": "2.2.2.2",
                "timestamp": pd.Timestamp("2026-03-10 00:01"),
                "path": "/",
                "status": 500,
            },
        ]
    )
    print(basic_aggregate_features(df))
