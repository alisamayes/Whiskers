"""Generate realistic Linux auth.log / secure style lines for Whiskers."""

from __future__ import annotations

import datetime
import random

from simulator.user import IPS_NORMAL

AUTH_HOSTNAME = "app-server-01"

AUTH_USERS = [
    "alice",
    "bob",
    "deploy",
    "git",
    "ci-runner",
    "backup",
    "ubuntu",
    "build",
    "monitor",
    "svc-api",
]

SUDO_TARGET_USERS = ["root", "root", "postgres", "deploy", "www-data"]

SUDO_PWDS = [
    "/var/www/html",
    "/tmp",
    "/opt/app",
    "/srv/data",
    "/etc/nginx",
]

SUDO_COMMANDS = [
    "/bin/ls -la /var/log",
    "/usr/bin/journalctl -u ssh -n 50 --no-pager",
    "/bin/systemctl status nginx",
    "/usr/bin/apt-get -s upgrade",
    "/bin/cat /etc/nginx/nginx.conf",
    "/usr/bin/tail -n 100 /var/log/auth.log",
    "/bin/ss -tlnp",
    "/usr/bin/df -h",
]


def format_trad_syslog_ts(dt: datetime.datetime) -> str:
    """RFC3164-style date (no year), e.g. ``Mar 27 14:32:01``."""
    return f"{dt.strftime('%b')} {dt.day:>2} {dt.strftime('%H:%M:%S')}"


def _random_sshd_pid() -> int:
    return random.randint(900, 65520)


def _random_ssh_port() -> int:
    return random.choice([22, 22, 22, 22, 2222])


def format_auth_ml_suffix(classification: str = "normal", count: int = 0) -> str:
    """Trailing fields for supervised / ground-truth (same idea as access.log)."""
    return f" {classification} {count}"


def generate_auth_normal_event(
    current_time: datetime.datetime,
    *,
    classification: str = "normal",
    count: int = 0,
) -> tuple[str, datetime.datetime]:
    """One plausible normal auth event: SSH success or sudo COMMAND= line.

    Returns ``(line, new_time)`` with ``new_time`` slightly after ``current_time``.
    """
    ts = format_trad_syslog_ts(current_time)
    host = AUTH_HOSTNAME
    ip = random.choice(IPS_NORMAL)
    user = random.choice(AUTH_USERS)
    port = _random_ssh_port()
    pid = _random_sshd_pid()
    suffix = format_auth_ml_suffix(classification, count)

    roll = random.random()
    if roll < 0.52:
        line = (
            f"{ts} {host} sshd[{pid}]: Accepted publickey for {user} "
            f"from {ip} port {port} ssh2{suffix}"
        )
    elif roll < 0.82:
        line = (
            f"{ts} {host} sshd[{pid}]: Accepted password for {user} "
            f"from {ip} port {port} ssh2{suffix}"
        )
    else:
        invoking = user
        target = random.choice(SUDO_TARGET_USERS)
        pwd = random.choice([f"/home/{invoking}", *SUDO_PWDS])
        tty = random.choice(["pts/0", "pts/1", "pts/2", "pts/3", "ssh"])
        cmd = random.choice(SUDO_COMMANDS)
        line = (
            f"{ts} {host} sudo:   {invoking} : TTY={tty} ; PWD={pwd} ; "
            f"USER={target} ; COMMAND={cmd}{suffix}"
        )

    delta_ms = random.randint(40, 1400)
    new_time = current_time + datetime.timedelta(milliseconds=delta_ms)
    return line, new_time


def generate_auth_normal_burst(
    current_time: datetime.datetime,
    n_events: int,
    *,
    classification: str = "normal",
    count: int = 0,
) -> tuple[list[str], datetime.datetime]:
    """Emit ``n_events`` chronological auth lines, advancing time between each."""
    lines: list[str] = []
    t = current_time
    for _ in range(max(0, n_events)):
        line, t = generate_auth_normal_event(t, classification=classification, count=count)
        lines.append(line)
    return lines, t
