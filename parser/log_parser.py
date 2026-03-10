import re
import pandas as pd

# Example log line: 103.44.12.9 - - [10/Mar/2026:08:30:47] "GET /admin HTTP/1.1" 404 532 "curl/7.68 | directory scan"
# 45.33.22.11 - - [10/Mar/2026:08:34:37] "POST /login HTTP/1.1" 401 532 "curl/7.68 | brute force"
#pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(GET|POST) (.*?) HTTP/1.1" (\d+) \d+ "(.*?)"'
pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(GET|POST) (.*?) HTTP/1.1" (\d+) \d+ "(.*?)"(?: (\w+(?:_\w+)*) (\d+))?'


def parse_logs(file):

    logs = []

    with open(file) as f:

        for line in f:

            match = re.search(pattern, line)

            if match:

                ip, timestamp, method, path, status, agent, classification, count = match.groups()

                logs.append({
                    "ip": ip,
                    "timestamp": timestamp,
                    "method": method,
                    "path": path,
                    "status": int(status),
                    "agent": agent,
                    "classification": classification,
                    "count": count
                })

    df = pd.DataFrame(logs)

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        format="%d/%b/%Y:%H:%M:%S"
    )

    df = df.sort_values("timestamp")

    return df