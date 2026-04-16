import datetime
import random

from simulator.user import IPS_ATTACK, IPS_NORMAL

PATHS_NORMAL = [
    "/",
    "/products",
    "/about",
    "/contact",
    "/login",
    "/dashboard",
    "/home",
    "/blog",
    "/api/v1/users",
    "/search",
    "/cart",
    "/checkout",
    "/profile",
    "/settings",
    "/help",
]

SQLI_PATTERNS = [
    "/search?q=' OR 1=1 --",
    "/search?q=%22 OR %221%22=%221",
    "/login?user=admin'--",
    "/products?id=1 UNION SELECT username, password FROM users",
    "/items?id=1; DROP TABLE users",
]

EXFIL_PATHS = [
    "/backup/full-backup.tar.gz",
    "/exports/users.csv",
    "/reports/financial-q4.pdf",
    "/db/dump.sql",
]

SCAN_PATHS = [
    "/admin",
    "/admin/login",
    "/admin/config",
    "/backup",
    "/.env",
    "/phpmyadmin",
    "/wp-admin",
    "/wp-login.php",
    "/config.php",
    "/server-status",
    "/.git/config",
    "/xmlrpc.php",
    "/.htaccess",
    "/phpinfo.php",
    "/test.php",
]

COMMAND_INJECTION_PATTERNS = [
    "/search?q=test;<simulated-command>",
    "/status?check=value&&<simulated-command>",
    "/ping?target=example.com||<simulated-command>",
    "/debug?mode=$(<simulated-command>)",
    "/info?cmd=`<simulated-command>`",
    "/action?input=value|<simulated-command>",
    "/run?x=test%3B<simulated-command>",
    "/run?x=test%253B<simulated-command>",
    "/probe?id=<simulated-command>_delay_test",
    "/file?name=data;<simulated-command>",
    "/calculate?num=10;<simulated-command>",
    "/tools/exec/<simulated-command>_attempt",
    "/check?param=value;;;<simulated-command>",
    "/submit?value=$(echo+test)|<simulated-command>",
]

USER_AGENTS = [
    "Mozilla/5.0",
    "Chrome/120.0",
    "Safari/17",
    "curl/7.68",
    "Firefox/120.0",
    "Edge/120.0",
    "Opera/90.0",
    "PostmanRuntime/7.32.3",
    "python-requests/2.28.1",
    "Go-http-client/1.1",
    "Wget/1.21.3",
    "Java/11.0.18",
]


def generate_normal_request(current_time):
    """Generate a single normal access request and advance simulated time."""
    ip = random.choice(IPS_NORMAL)
    path = random.choice(PATHS_NORMAL)
    status = random.choice([200, 200, 200, 200, 200, 404])
    agent = random.choice(USER_AGENTS)
    bytes_sent = random.randint(300, 5000)

    time_str = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
    log = (
        f'{ip} - - [{time_str}] "GET {path} HTTP/1.1" '
        f'{status} {bytes_sent} "-" "{agent}" normal'
    )

    new_time = current_time + datetime.timedelta(seconds=random.randint(1, 5))
    return log, new_time


def brute_force_attack(ip, current_time, count):
    """Generate an access-log login brute-force burst from one IP."""
    logs = []
    attempts = random.randint(20, 40)

    for _ in range(attempts):
        time = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        bytes_sent = random.randint(300, 1500)
        logs.append(
            f'{ip} - - [{time}] "POST /login HTTP/1.1" 401 {bytes_sent} "-" '
            f'"curl/7.68" access_brute_force {count}'
        )
        current_time += datetime.timedelta(seconds=1)

    return logs, current_time


def directory_scan(ip, current_time, count):
    """Generate a directory scanning sequence across common sensitive paths."""
    logs = []
    for path in SCAN_PATHS:
        time = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        bytes_sent = random.randint(300, 2000)
        logs.append(
            f'{ip} - - [{time}] "GET {path} HTTP/1.1" 404 {bytes_sent} "-" '
            f'"curl/7.68" access_directory_scan {count}'
        )
        current_time += datetime.timedelta(seconds=1)

    return logs, current_time


def request_flood(ip, current_time, count):
    """Generate high-rate normal-path requests to simulate traffic flooding."""
    logs = []
    for _ in range(100):
        path = random.choice(PATHS_NORMAL)
        time = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        bytes_sent = random.randint(300, 4000)
        logs.append(
            f'{ip} - - [{time}] "GET {path} HTTP/1.1" 200 {bytes_sent} "-" '
            f'"curl/7.68" access_request_flood {count}'
        )
        current_time += datetime.timedelta(milliseconds=200)

    return logs, current_time


def sql_injection_attack(ip, current_time, count):
    """Generate SQL injection probe requests with error-like status codes."""
    logs = []
    for path in SQLI_PATTERNS:
        time = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        status = random.choice([400, 500])
        bytes_sent = random.randint(500, 5000)
        logs.append(
            f'{ip} - - [{time}] "GET {path} HTTP/1.1" {status} {bytes_sent} "-" '
            f'"curl/7.68" access_sql_injection {count}'
        )
        current_time += datetime.timedelta(seconds=3)

    return logs, current_time


def exfiltration_attack(ip, current_time, count):
    """Generate large-response requests that mimic data exfiltration."""
    logs = []
    for path in EXFIL_PATHS:
        time = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        status = 200
        bytes_sent = random.randint(50_000_000, 200_000_000)
        logs.append(
            f'{ip} - - [{time}] "GET {path} HTTP/1.1" {status} {bytes_sent} "-" '
            f'"curl/7.68" access_data_exfiltration {count}'
        )
        current_time += datetime.timedelta(seconds=5)

    return logs, current_time


def command_injection_attack(ip, current_time, count):
    """Generate command-injection style request patterns against endpoints."""
    logs = []
    max_patterns = len(COMMAND_INJECTION_PATTERNS)
    temp = COMMAND_INJECTION_PATTERNS.copy()
    attack_count = random.randint(5, max_patterns)

    for _ in range(attack_count):
        time = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        status = random.choice([500, 403, 200])
        bytes_sent = random.randint(300, 1500)
        agent = random.choice(USER_AGENTS)
        command_choice = random.choice(temp)
        temp.remove(command_choice)
        logs.append(
            f'{ip} - - [{time}] "GET {command_choice} HTTP/1.1" {status} {bytes_sent} "-" '
            f'"{agent}" access_command_injection {count}'
        )
        current_time += datetime.timedelta(seconds=2)

    return logs, current_time
