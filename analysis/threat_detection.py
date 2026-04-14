"""Legacy threat detection helpers (deprecated).

Use detectors in ``analysis/detectors`` for all new integrations.
"""

import warnings

warnings.warn(
    "analysis.threat_detection is deprecated; use analysis.detectors instead.",
    DeprecationWarning,
    stacklevel=2,
)


class Mäuschen_Detective_Tools:
    def __init__(self):
        pass

    
    def detect_bruteforce(self,df):

        failed = df[
            (df["path"] == "/login") &
            (df["status"] == 401)
        ].copy()

        failed = failed.set_index("timestamp")

        attempts = failed.groupby("ip").resample("1min").size()

        alerts = attempts[attempts > 10]

        return alerts



    def detect_scanning(self,df):

        # Look for IPs with many 404 errors on different paths in a short time
        failed_requests = df[df["status"] == 404].copy()
        failed_requests = failed_requests.set_index("timestamp")

        # Group by IP and resample to 30 seconds, count unique paths with 404
        path_counts = failed_requests.groupby("ip").resample("30s")["path"].nunique()

        # Alert if more than 4 unique 404 paths in 30 seconds
        alerts = path_counts[path_counts > 4]

        return alerts



    def detect_request_flood(self,df):

        df = df.sort_values("timestamp")
        df = df.set_index("timestamp")

        alerts = []

        for ip, group in df.groupby("ip"):

            rolling_counts = group["path"].rolling("60s").count()

            flood_points = rolling_counts[rolling_counts > 80]

            last_alert_time = None

            for time, count in flood_points.items():

                if last_alert_time is None or (time - last_alert_time).total_seconds() > 60:
                    alerts.append((ip, time, int(count)))
                    last_alert_time = time

        return alerts