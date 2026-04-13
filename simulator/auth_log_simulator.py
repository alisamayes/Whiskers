"""Generate realistic Linux auth.log / secure style lines for Whiskers."""

from __future__ import annotations

import datetime
import random

from simulator.user import IPS_NORMAL

AUTH_HOSTNAME = "app-server-01"

# Supervised / ground-truth labels (trailer on each line in the episode)
AUTH_CLASS_SSH_BRUTEFORCE = "auth_ssh_bruteforce"
AUTH_CLASS_SSH_USER_ENUM = "auth_ssh_user_enum"
AUTH_CLASS_SUDO_BRUTEFORCE = "auth_sudo_bruteforce"
AUTH_CLASS_PRIVLAGE_ESCALATION_CHAIN = "auth_privilege_escalation"

SSH_BRUTEFORCE_TARGETS = [
    "root",
    "admin",
    "test",
    "postgres",
    "oracle",
    "git",
    "backup",
    "ubuntu",
    "www-data",
    "deploy",
    "guest",
    "user",
]

SSH_ENUM_RANDOM_PREFIXES = ["svc", "scan", "test", "tmp", "bx", "z", "u", "sql", "ftp", "vpn"]

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


def _advance_time(
    t: datetime.datetime,
    *,
    min_ms: int = 200,
    max_ms: int = 2800,
) -> datetime.datetime:
    return t + datetime.timedelta(milliseconds=random.randint(min_ms, max_ms))


def _random_enum_username() -> str:
    p = random.choice(SSH_ENUM_RANDOM_PREFIXES)
    return f"{p}_{random.randint(100, 99999)}"


def auth_ssh_bruteforce_attack(
    ip: str,
    current_time: datetime.datetime,
    count: int,
) -> tuple[list[str], datetime.datetime]:
    """SSH password-guessing burst: mixed ``Failed password`` / invalid-user lines from one IP.

    Realistic pattern: many attempts in seconds, same ``sshd`` pid common within a short window.
    Each line ends with ``{AUTH_CLASS_SSH_BRUTEFORCE} {count}`` for supervised labels.
    """
    lines: list[str] = []
    t = current_time
    host = AUTH_HOSTNAME
    port = _random_ssh_port()
    pid = _random_sshd_pid()
    suffix = format_auth_ml_suffix(AUTH_CLASS_SSH_BRUTEFORCE, count)
    attempts = random.randint(18, 36)

    for _ in range(attempts):
        ts = format_trad_syslog_ts(t)
        roll = random.random()
        if roll < 0.38:
            user = random.choice(SSH_BRUTEFORCE_TARGETS)
            lines.append(
                f"{ts} {host} sshd[{pid}]: Failed password for invalid user {user} "
                f"from {ip} port {port} ssh2{suffix}"
            )
        elif roll < 0.78:
            user = random.choice(SSH_BRUTEFORCE_TARGETS)
            lines.append(
                f"{ts} {host} sshd[{pid}]: Failed password for {user} "
                f"from {ip} port {port} ssh2{suffix}"
            )
        else:
            user = _random_enum_username()
            lines.append(
                f"{ts} {host} sshd[{pid}]: Failed password for invalid user {user} "
                f"from {ip} port {port} ssh2{suffix}"
            )
        t = _advance_time(t, min_ms=150, max_ms=2400)

    return lines, t


def auth_ssh_user_enum_attack(
    ip: str,
    current_time: datetime.datetime,
    count: int,
) -> tuple[list[str], datetime.datetime]:
    """SSH username enumeration: mostly ``Invalid user`` probes from one IP.

    Occasionally interleaved with ``Failed password for invalid user`` (common in scans).
    """
    lines: list[str] = []
    t = current_time
    host = AUTH_HOSTNAME
    port = _random_ssh_port()
    pid = _random_sshd_pid()
    suffix = format_auth_ml_suffix(AUTH_CLASS_SSH_USER_ENUM, count)
    attempts = random.randint(22, 55)

    for _ in range(attempts):
        ts = format_trad_syslog_ts(t)
        if random.random() < 0.82:
            user = _random_enum_username()
            lines.append(
                f"{ts} {host} sshd[{pid}]: Invalid user {user} from {ip} port {port} ssh2{suffix}"
            )
        else:
            user = _random_enum_username()
            lines.append(
                f"{ts} {host} sshd[{pid}]: Failed password for invalid user {user} "
                f"from {ip} port {port} ssh2{suffix}"
            )
        t = _advance_time(t, min_ms=80, max_ms=1800)

    return lines, t


def auth_sudo_bruteforce_attack(
    ip: str,
    current_time: datetime.datetime,
    count: int,
) -> tuple[list[str], datetime.datetime]:
    """Repeated ``sudo`` PAM auth failures (local session), realistic ``pam_unix(sudo:auth)`` lines.

    ``ip`` is kept for signature parity with other auth attacks; sudo lines are local
    (``rhost=`` empty) like typical single-host auth.log entries.
    """
    _ = ip
    lines: list[str] = []
    t = current_time
    host = AUTH_HOSTNAME
    suffix = format_auth_ml_suffix(AUTH_CLASS_SUDO_BRUTEFORCE, count)
    ruser = random.choice(AUTH_USERS)
    uid = random.randint(1000, 65534)
    tty_n = random.randint(0, 6)
    attempts = random.randint(6, 16)

    for _ in range(attempts):
        ts = format_trad_syslog_ts(t)
        target = random.choice(["root", "root", "root", "postgres", "www-data"])
        # Debian/Ubuntu-style pam_unix sudo failure (rhost often empty on console/SSH TTY)
        lines.append(
            f"{ts} {host} sudo: pam_unix(sudo:auth): authentication failure; "
            f"logname={ruser} uid={uid} euid=0 tty=/dev/pts/{tty_n} "
            f"ruser={ruser} rhost=  user={target}{suffix}"
        )
        t = _advance_time(t, min_ms=400, max_ms=4500)

    return lines, t


def auth_privilege_escalation_attack(
    ip: str,
    current_time: datetime.datetime,
    count: int,
) -> tuple[list[str], datetime.datetime]:
    """Simulate post-compromise escalation: SSH success then repeated sudo auth failures.

    Ground-truth trailer ``auth_privilege_escalation {count}`` on every line in the episode.
    """
    lines: list[str] = []
    t = current_time
    host = AUTH_HOSTNAME
    suffix = format_auth_ml_suffix(AUTH_CLASS_PRIVLAGE_ESCALATION_CHAIN, count)
    user = random.choice(["deploy", "ubuntu", "ci-runner", "backup", "build"])
    port = _random_ssh_port()
    pid = _random_sshd_pid()

    ts = format_trad_syslog_ts(t)
    lines.append(
        f"{ts} {host} sshd[{pid}]: Accepted password for {user} "
        f"from {ip} port {port} ssh2{suffix}"
    )
    t = _advance_time(t, min_ms=800, max_ms=5200)

    uid = random.randint(1000, 65534)
    tty_n = random.randint(0, 6)
    n_fail = random.randint(3, 7)
    for _ in range(n_fail):
        ts = format_trad_syslog_ts(t)
        target = random.choice(["root", "root", "root", "postgres", "www-data"])
        lines.append(
            f"{ts} {host} sudo: pam_unix(sudo:auth): authentication failure; "
            f"logname={user} uid={uid} euid=0 tty=/dev/pts/{tty_n} "
            f"ruser={user} rhost=  user={target}{suffix}"
        )
        t = _advance_time(t, min_ms=300, max_ms=3800)

    ts = format_trad_syslog_ts(t)
    pwd = f"/home/{user}"
    cmd = random.choice(
        [
            "/bin/cat /etc/shadow",
            "/usr/bin/id",
            "/bin/bash",
            "/usr/bin/chmod +s /tmp/.hidden",
        ]
    )
    lines.append(
        f"{ts} {host} sudo:   {user} : TTY=pts/{tty_n} ; PWD={pwd} ; "
        f"USER=root ; COMMAND={cmd}{suffix}"
    )
    t = _advance_time(t, min_ms=200, max_ms=1500)

    return lines, t


# Registry for callers (e.g. log generator, tests)
AUTH_ATTACK_FUNCTIONS = {
    AUTH_CLASS_SSH_BRUTEFORCE: auth_ssh_bruteforce_attack,
    AUTH_CLASS_SSH_USER_ENUM: auth_ssh_user_enum_attack,
    AUTH_CLASS_SUDO_BRUTEFORCE: auth_sudo_bruteforce_attack,
    AUTH_CLASS_PRIVLAGE_ESCALATION_CHAIN: auth_privilege_escalation_attack,
}
