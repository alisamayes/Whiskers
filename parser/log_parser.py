from __future__ import annotations

import re
from datetime import datetime

import pandas as pd

# Access log pattern
# Example line:
# 103.78.90.123 - - [23/Mar/2026:10:45:09 +0000] "POST /login HTTP/1.1" 401 659 "-" "curl/7.68" access_brute_force 0
# Note: the last two fields are for ML classifaction only and rule based detection ignores it.

ACCESS_PATTERN = (
    r"(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "
    r'"(GET|POST) ([^"]*) HTTP/1.1" '
    r'(\d+) (\d+) "(.*?)" "(.*?)"(?:\s+(\w+(?:_\w+)*))?(?:\s+(\d+))?'
)


# Simple firewall log pattern (example):
# 2026-03-10T12:00:01Z FIREWALL ALLOW src=1.2.3.4 dst=5.6.7.8 dport=443 proto=tcp bytes=1234
FIREWALL_PATTERN = (
    r"(\S+)\s+FIREWALL\s+(ALLOW|DENY)\s+src=([\d\.]+)\s+dst=([\d\.]+)\s+"
    r"dport=(\d+)\s+proto=(\w+)\s+bytes=(\d+)"
)

# Linux auth / syslog (after hostname): sshd[pid]: ... or sudo: ...
# Traditional syslog prefix:
#   Mar 27 10:00:00 hostname sshd[12345]: Failed password for root from 192.168.1.1 port 22 ssh2
# ISO8601-style prefix:
#   2026-03-27T10:00:00.123456+00:00 hostname sshd[12345]: ...
_SYSLOG_ISO_PREFIX = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}(?::?\d{2})?)?)\s+\S+\s+(.+)$"
)
_SYSLOG_TRAD_PREFIX = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(.+)$"
)
_SSHD_PAYLOAD = re.compile(r"^sshd\[\d+\]:\s*(.+)$")
_SUDO_PAYLOAD = re.compile(r"^sudo:\s*(.+)$")

# Remote IP after "from" (IPv4 or IPv6 token; no brackets in typical OpenSSH lines)
_SSH_FROM_PORT = re.compile(r"\bfrom\s+(\S+)\s+port\s+(\d+)\b")

_SSH_FAILED_INVALID_USER = re.compile(
    r"Failed password for invalid user (\S+) from (\S+) port (\d+)"
)
_SSH_FAILED_USER = re.compile(r"Failed password for (\S+) from (\S+) port (\d+)")
_SSH_INVALID_USER = re.compile(r"Invalid user (\S+) from (\S+) port (\d+)")
_SSH_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive) for (\S+) from (\S+) port (\d+)"
)

_SUDO_COMMAND = re.compile(
    r"^\s*(\S+)\s*:\s+.*?\bUSER=(\S+)\s*;\s*COMMAND=(.+)$",
    re.DOTALL,
)
_SUDO_AUTH_FAIL = re.compile(
    r"pam_unix\(sudo:auth\): authentication failure(?:.*?\bruser=(\S+))?",
    re.DOTALL,
)

# Optional Whiskers simulator / ML trailer (same convention as access.log):
#   ... ssh2 normal 0
_AUTH_ML_TRAILER = re.compile(r"\s+(\w+(?:_\w+)*)\s+(\d+)\s*$")


def read_text_lines_safe(
    file_path: str, *, quiet: bool = True
) -> tuple[list[str], str | None]:
    """Read UTF-8 text lines safely and return ``(lines, error_message)``."""
    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            return f.readlines(), None
    except OSError as e:
        msg = f"Could not read {file_path}: {e}"
        if not quiet:
            print(msg)
        return [], msg


def _parse_syslog_timestamp(ts_raw: str) -> pd.Timestamp:
    """Parse syslog timestamp string to a timezone-aware UTC pandas Timestamp."""
    ts_raw = ts_raw.strip()
    if not ts_raw:
        return pd.NaT
    if ts_raw[0].isdigit() and "T" in ts_raw:
        return pd.to_datetime(ts_raw, utc=True, errors="coerce")
    try:
        dt = datetime.strptime(ts_raw, "%b %d %H:%M:%S")
        dt = dt.replace(year=datetime.now().year)
        return pd.Timestamp(dt, tz="UTC")
    except ValueError:
        return pd.to_datetime(ts_raw, utc=True, errors="coerce")


def _auth_row(
    *,
    ip: str,
    timestamp: pd.Timestamp,
    method: str,
    path: str,
    status: int,
    agent: str,
    classification: str,
    log_source: str,
    referer: str = "",
    bytes_sent: int = 0,
    count: int = 0,
    service: str | None = None,
    auth_user: str | None = None,
    ssh_port: int | None = None,
) -> dict:
    row = {
        "ip": ip,
        "timestamp": timestamp,
        "method": method,
        "path": path,
        "status": status,
        "bytes_sent": bytes_sent,
        "referer": referer,
        "agent": agent,
        "classification": classification,
        "count": count,
        "log_source": log_source,
    }
    if service is not None:
        row["service"] = service
    if auth_user is not None:
        row["auth_user"] = auth_user
    if ssh_port is not None:
        row["ssh_port"] = ssh_port
    return row


def _parse_sshd_body(body: str, ts: pd.Timestamp, log_source: str) -> dict | None:
    """Map OpenSSH log message body to one common-schema row, or None if skipped."""

    m = _SSH_FAILED_INVALID_USER.search(body)
    if m:
        user, ip, port_s = m.groups()
        return _auth_row(
            ip=ip,
            timestamp=ts,
            method="SSH",
            path="ssh/failed_password",
            status=401,
            agent="sshd",
            classification="normal",
            log_source=log_source,
            service="sshd",
            auth_user=user,
            ssh_port=int(port_s),
        )

    m = _SSH_FAILED_USER.search(body)
    if m:
        user, ip, port_s = m.groups()
        if user == "invalid":
            return None
        return _auth_row(
            ip=ip,
            timestamp=ts,
            method="SSH",
            path="ssh/failed_password",
            status=401,
            agent="sshd",
            classification="normal",
            log_source=log_source,
            service="sshd",
            auth_user=user,
            ssh_port=int(port_s),
        )

    m = _SSH_INVALID_USER.search(body)
    if m:
        user, ip, port_s = m.groups()
        return _auth_row(
            ip=ip,
            timestamp=ts,
            method="SSH",
            path="ssh/invalid_user",
            status=401,
            agent="sshd",
            classification="normal",
            log_source=log_source,
            service="sshd",
            auth_user=user,
            ssh_port=int(port_s),
        )

    m = _SSH_ACCEPTED.search(body)
    if m:
        user, ip, port_s = m.groups()
        return _auth_row(
            ip=ip,
            timestamp=ts,
            method="SSH",
            path="ssh/accepted",
            status=200,
            agent="sshd",
            classification="normal",
            log_source=log_source,
            service="sshd",
            auth_user=user,
            ssh_port=int(port_s),
        )

    return None


def _parse_sudo_body(body: str, ts: pd.Timestamp, log_source: str) -> dict | None:
    m = _SUDO_COMMAND.match(body.strip())
    if m:
        invoking, target_user, command = m.groups()
        command = command.strip()
        path = "sudo/command"
        return _auth_row(
            ip="127.0.0.1",
            timestamp=ts,
            method="SUDO",
            path=path,
            status=200,
            agent="sudo",
            classification="normal",
            log_source=log_source,
            service="sudo",
            auth_user=invoking.strip(),
            referer=target_user,
        )

    if _SUDO_AUTH_FAIL.search(body):
        ip = "127.0.0.1"
        m_ip = _SSH_FROM_PORT.search(body)
        if m_ip:
            ip = m_ip.group(1)
        ruser_m = re.search(r"\bruser=(\S+)", body)
        auth_user = ruser_m.group(1) if ruser_m else None
        return _auth_row(
            ip=ip,
            timestamp=ts,
            method="SUDO",
            path="sudo/auth_failure",
            status=401,
            agent="sudo",
            classification="normal",
            log_source=log_source,
            service="sudo",
            auth_user=auth_user,
        )

    return None


def parse_auth_logs(file, source: str = "auth"):
    """Parse Linux auth-style syslog lines into the common Whiskers schema.

    Supports typical OpenSSH (sshd) and sudo entries from auth.log / secure.
    Unrecognized lines are skipped. Remote SSH events set ``ip`` to the
    connecting address; local sudo sessions use 127.0.0.1 unless rhost= is present.

    Schema alignment:
      * ``method`` — SSH, SUDO
      * ``path`` — synthetic event id (e.g. ssh/failed_password, sudo/command)
      * ``status`` — 200 success, 401 failed auth (for feature error_rate)
      * ``referer`` — for sudo COMMAND= lines, holds USER= target; otherwise empty
    """

    rows: list[dict] = []
    lines, _ = read_text_lines_safe(file)
    for line in lines:
        line = line.strip()
        if not line:
            continue

        classification = "normal"
        count = 0
        trailer_m = _AUTH_ML_TRAILER.search(line)
        if trailer_m:
            classification = trailer_m.group(1)
            count = int(trailer_m.group(2))
            line = line[: trailer_m.start()].rstrip()

        msg = None
        ts_raw = None
        iso_m = _SYSLOG_ISO_PREFIX.match(line)
        trad_m = _SYSLOG_TRAD_PREFIX.match(line)
        if iso_m:
            ts_raw, msg = iso_m.group(1), iso_m.group(2)
        elif trad_m:
            ts_raw, msg = trad_m.group(1), trad_m.group(2)
        else:
            continue

        ts = _parse_syslog_timestamp(ts_raw)
        if pd.isna(ts):
            continue

        row_dict = None
        sshd_m = _SSHD_PAYLOAD.match(msg)
        if sshd_m:
            row_dict = _parse_sshd_body(sshd_m.group(1), ts, source)
        else:
            sudo_m = _SUDO_PAYLOAD.match(msg)
            if sudo_m:
                row_dict = _parse_sudo_body(sudo_m.group(1), ts, source)

        if row_dict is not None:
            row_dict["classification"] = classification
            row_dict["count"] = count
            rows.append(row_dict)

    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values("timestamp")

    return df


def parse_logs(file, source: str = "access", *, quiet: bool = False):

    logs = []
    lines, _ = read_text_lines_safe(file, quiet=quiet)
    for line in lines:

        match = re.search(ACCESS_PATTERN, line)
        if not match and not quiet:
            print("NO MATCH: ", line)

        if match:

            (
                ip,
                timestamp,
                method,
                path,
                status,
                bytes_sent,
                referer,
                agent,
                classification,
                count,
            ) = match.groups()

            logs.append(
                {
                    "ip": ip,
                    "timestamp": timestamp,
                    "method": method,
                    "path": path,
                    "status": int(status),
                    "bytes_sent": int(bytes_sent),
                    "referer": referer,
                    "agent": agent,
                    "classification": (
                        classification if classification is not None else "normal"
                    ),
                    "count": int(count) if count is not None else 0,
                    "log_source": source,
                }
            )

    df = pd.DataFrame(logs)

    if not df.empty:
        df["timestamp"] = pd.to_datetime(
            df["timestamp"],
            format="%d/%b/%Y:%H:%M:%S %z",
            utc=True,
            errors="coerce",
        )
        df = df.dropna(subset=["timestamp"])
        df = df.sort_values("timestamp")

    return df


def parse_firewall_logs(file, source: str = "firewall"):
    """Parse simple firewall logs into the common schema.

    Example line:
    2026-03-10T12:00:01Z FIREWALL ALLOW src=1.2.3.4 dst=5.6.7.8 dport=443 proto=tcp bytes=1234
    """

    rows = []
    lines, _ = read_text_lines_safe(file)
    for line in lines:
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
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
        df = df.dropna(subset=["timestamp"])
        df = df.sort_values("timestamp")

    return df
