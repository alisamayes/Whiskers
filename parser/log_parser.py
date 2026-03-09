import re
import pandas as pd

pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(GET|POST) (.*?) HTTP/1.1" (\d+) \d+ "(.*?)"'


def parse_logs(file):

    logs = []

    with open(file) as f:

        for line in f:

            match = re.search(pattern, line)

            if match:

                ip, timestamp, method, path, status, agent = match.groups()

                logs.append({
                    "ip": ip,
                    "timestamp": timestamp,
                    "method": method,
                    "path": path,
                    "status": int(status),
                    "agent": agent
                })

    df = pd.DataFrame(logs)

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        format="%d/%b/%Y:%H:%M:%S"
    )

    df = df.sort_values("timestamp")

    return df