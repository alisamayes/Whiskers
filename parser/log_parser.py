import re
import pandas as pd

# Access log pattern
# Example line:
# 103.44.12.9 - - [10/Mar/2026:08:30:47] "GET /admin HTTP/1.1" 404 532 "curl/7.68" directory_scan 3
ACCESS_PATTERN = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(GET|POST) (.*?) HTTP/1.1" (\d+) (\d+) "(.*?)"(?: (\w+(?:_\w+)*) (\d+))?'

# Simple firewall log pattern (example):
# 2026-03-10T12:00:01Z FIREWALL ALLOW src=1.2.3.4 dst=5.6.7.8 dport=443 proto=tcp bytes=1234
FIREWALL_PATTERN = (
    r'(\S+)\s+FIREWALL\s+(ALLOW|DENY)\s+src=([\d\.]+)\s+dst=([\d\.]+)\s+'
    r'dport=(\d+)\s+proto=(\w+)\s+bytes=(\d+)'
)


def parse_logs(file, source: str = "access"):

    logs = []

    with open(file) as f:

        for line in f:

            match = re.search(ACCESS_PATTERN, line)

            if match:

                ip, timestamp, method, path, status, bytes_sent, agent, classification, count = match.groups()

                logs.append({
                    "ip": ip,
                    "timestamp": timestamp,
                    "method": method,
                    "path": path,
                    "status": int(status),
                    "bytes_sent": int(bytes_sent),
                    "agent": agent,
                    "classification": classification if classification is not None else "normal",
                    "count": int(count) if count is not None else 0,
                    "log_source": source,
                })

    df = pd.DataFrame(logs)

    if not df.empty:
        df["timestamp"] = pd.to_datetime(
            df["timestamp"],
            format="%d/%b/%Y:%H:%M:%S"
        )
        df = df.sort_values("timestamp")

    return df




def parse_firewall_logs(file, source: str = "firewall"):
    """Parse simple firewall logs into the common schema.

    Example line:
    2026-03-10T12:00:01Z FIREWALL ALLOW src=1.2.3.4 dst=5.6.7.8 dport=443 proto=tcp bytes=1234
    """

    rows = []
    with open(file) as f:
        for line in f:
            m = re.search(FIREWALL_PATTERN, line)
            if not m:
                continue

            ts, action, src_ip, dst_ip, dport, proto, bytes_sent = m.groups()

            rows.append(
                {
                    "ip": src_ip,
                    "timestamp": ts,
                    # map firewall fields into the generic schema
                    "method": "FIREWALL",
                    "path": f"{dst_ip}:{dport}/{proto.lower()}",
                    "status": 0,
                    "bytes_sent": int(bytes_sent),
                    "agent": "firewall",
                    "classification": action.lower(),  # allow / deny
                    "count": 0,
                    "log_source": source,
                    "dst_ip": dst_ip,
                    "dst_port": int(dport),
                    "protocol": proto.lower(),
                    "action": action.upper(),
                }
            )

    df = pd.DataFrame(rows)

    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("timestamp")


    return df
