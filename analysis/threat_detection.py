

def detect_bruteforce(df):

    failed = df[
        (df["path"] == "/login") &
        (df["status"] == 401)
    ].copy()

    failed = failed.set_index("timestamp")

    attempts = failed.groupby("ip").resample("1min").size()

    alerts = attempts[attempts > 10]

    return alerts



def detect_scanning(df):

    df = df.set_index("timestamp")

    path_counts = df.groupby("ip").resample("1min")["path"].nunique()

    alerts = path_counts[path_counts > 5]

    return alerts



def detect_request_flood(df):

    df = df.sort_values("timestamp")
    df = df.set_index("timestamp")

    alerts = []

    for ip, group in df.groupby("ip"):

        rolling_counts = group["path"].rolling("60s").count()

        flood_points = rolling_counts[rolling_counts > 100]

        last_alert_time = None

        for time, count in flood_points.items():

            if last_alert_time is None or (time - last_alert_time).total_seconds() > 60:
                alerts.append((ip, time, int(count)))
                last_alert_time = time

    return alerts