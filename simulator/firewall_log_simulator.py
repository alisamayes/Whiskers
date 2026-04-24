"""Generate realistic firewall log lines with optional labeled attack bursts."""

from __future__ import annotations

import datetime
import random

from simulator.user import IPS_ATTACK, IPS_NORMAL

FIREWALL_HOST = "fw-edge-01"

INTERNAL_DSTS = [
    "10.0.0.10",
    "10.0.0.20",
    "10.0.1.15",
    "172.16.0.8",
    "172.16.1.25",
    "192.168.1.50",
]

COMMON_TCP = [22, 80, 443, 8080, 8443, 3306, 5432]
COMMON_UDP = [53, 123, 500, 4500, 514, 1194]

SCANNED_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    8080,
    8443,
]


def _format_line(
    t: datetime.datetime,
    *,
    action: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    proto: str,
    bytes_sent: int,
    src_port: int,
    packets: int,
    classification: str = "normal",
    count: int = 0,
) -> str:
    ts = t.strftime("%Y-%m-%dT%H:%M:%SZ")
    return (
        f"{ts} host={FIREWALL_HOST} FIREWALL action={action} src={src_ip} "
        f"sport={src_port} dst={dst_ip} dport={dst_port} proto={proto} "
        f"packets={packets} bytes={bytes_sent} {classification} {count}"
    )


def generate_firewall_normal_event(
    current_time: datetime.datetime,
) -> tuple[str, datetime.datetime]:
    src_ip = random.choice(IPS_NORMAL)
    dst_ip = random.choice(INTERNAL_DSTS)
    proto = random.choice(["tcp", "tcp", "tcp", "udp"])
    dport = random.choice(COMMON_TCP if proto == "tcp" else COMMON_UDP)
    action = random.choice(["ALLOW", "ALLOW", "ALLOW", "DENY"])
    src_port = random.randint(1024, 65535)
    packets = random.randint(1, 14)
    bytes_sent = random.randint(120, 24_000)
    line = _format_line(
        current_time,
        action=action,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dport,
        proto=proto,
        src_port=src_port,
        packets=packets,
        bytes_sent=bytes_sent,
    )
    new_time = current_time + datetime.timedelta(milliseconds=random.randint(40, 900))
    return line, new_time


def firewall_port_scan_attack(
    ip: str, current_time: datetime.datetime, count: int
) -> tuple[list[str], datetime.datetime]:
    lines: list[str] = []
    t = current_time
    dst_ip = random.choice(INTERNAL_DSTS)
    attempts = random.randint(12, 26)
    for dport in random.sample(SCANNED_PORTS, k=min(attempts, len(SCANNED_PORTS))):
        line = _format_line(
            t,
            action="DENY",
            src_ip=ip,
            dst_ip=dst_ip,
            dst_port=dport,
            proto="tcp",
            src_port=random.randint(20000, 65535),
            packets=random.randint(1, 3),
            bytes_sent=random.randint(60, 360),
            classification="firewall_port_scan",
            count=count,
        )
        lines.append(line)
        t += datetime.timedelta(milliseconds=random.randint(50, 300))
    return lines, t


def firewall_blocked_ssh_bruteforce(
    ip: str, current_time: datetime.datetime, count: int
) -> tuple[list[str], datetime.datetime]:
    lines: list[str] = []
    t = current_time
    dst_ip = random.choice(INTERNAL_DSTS)
    attempts = random.randint(18, 42)
    for _ in range(attempts):
        line = _format_line(
            t,
            action="DENY",
            src_ip=ip,
            dst_ip=dst_ip,
            dst_port=22,
            proto="tcp",
            src_port=random.randint(20000, 65535),
            packets=random.randint(1, 4),
            bytes_sent=random.randint(64, 420),
            classification="firewall_blocked_ssh_bruteforce",
            count=count,
        )
        lines.append(line)
        t += datetime.timedelta(milliseconds=random.randint(120, 700))
    return lines, t


def firewall_syn_flood_attack(
    ip: str, current_time: datetime.datetime, count: int
) -> tuple[list[str], datetime.datetime]:
    lines: list[str] = []
    t = current_time
    dst_ip = random.choice(INTERNAL_DSTS)
    dport = random.choice([80, 443, 8080, 8443])
    bursts = random.randint(45, 95)
    for _ in range(bursts):
        line = _format_line(
            t,
            action="DENY",
            src_ip=ip,
            dst_ip=dst_ip,
            dst_port=dport,
            proto="tcp",
            src_port=random.randint(1024, 65535),
            packets=random.randint(2, 10),
            bytes_sent=random.randint(120, 1200),
            classification="firewall_syn_flood",
            count=count,
        )
        lines.append(line)
        t += datetime.timedelta(milliseconds=random.randint(10, 80))
    return lines, t


def firewall_denied_egress_exfiltration(
    ip: str, current_time: datetime.datetime, count: int
) -> tuple[list[str], datetime.datetime]:
    lines: list[str] = []
    t = current_time
    dst_ip = random.choice(IPS_ATTACK)
    attempts = random.randint(6, 15)
    for _ in range(attempts):
        line = _format_line(
            t,
            action="DENY",
            src_ip=ip,
            dst_ip=dst_ip,
            dst_port=random.choice([4444, 8088, 9001, 9443, 53]),
            proto=random.choice(["tcp", "udp"]),
            src_port=random.randint(1024, 65535),
            packets=random.randint(40, 220),
            bytes_sent=random.randint(500_000, 12_000_000),
            classification="firewall_denied_egress_exfiltration",
            count=count,
        )
        lines.append(line)
        t += datetime.timedelta(milliseconds=random.randint(300, 1400))
    return lines, t
