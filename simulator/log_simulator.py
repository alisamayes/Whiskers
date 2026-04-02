import os
import random
import datetime
import sys

from simulator.user import User, PROFILES, IPS_NORMAL, IPS_ATTACK
from simulator.auth_log_simulator import (
    AUTH_ATTACK_FUNCTIONS,
    AUTH_CLASS_SSH_BRUTEFORCE,
    AUTH_CLASS_SSH_USER_ENUM,
    AUTH_CLASS_SUDO_BRUTEFORCE,
    generate_auth_normal_burst,
    generate_auth_normal_event,
)
from analysis.stats import report_generation_stats


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
    "/help"
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
    "/test.php"
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
    "Java/11.0.18"
]




def generate_normal_request(current_time):
    """Generate a single normal request and advance time by a small random delta."""

    ip = random.choice(IPS_NORMAL)
    path = random.choice(PATHS_NORMAL)
    status = random.choice([200, 200, 200, 200, 200, 404])
    agent = random.choice(USER_AGENTS)
    # simulate different response sizes (in bytes)
    bytes_sent = random.randint(300, 5000)

    time_str = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
    log = f'{ip} - - [{time_str}] "GET {path} HTTP/1.1" {status} {bytes_sent} "-" "{agent}" normal'

    # Advance time by 1–5 seconds between normal requests
    new_time = current_time + datetime.timedelta(seconds=random.randint(1, 5))
    return log, new_time


def brute_force_attack(ip, current_time, count):

    logs = []
    attempts = random.randint(20, 40)  # Simulate 20-40 attempts to ensure we have at least one valid sequence

    for i in range(attempts):

        time = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")

        # failed login responses are usually small-ish
        bytes_sent = random.randint(300, 1500)
        logs.append(
            f'{ip} - - [{time}] "POST /login HTTP/1.1" 401 {bytes_sent} "-" "curl/7.68" brute_force {count}'
        )

        current_time += datetime.timedelta(seconds=1)

    return logs, current_time


def directory_scan(ip, current_time, count):

    logs = []

    for path in SCAN_PATHS:

        time = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")

        bytes_sent = random.randint(300, 2000)
        logs.append(
            f'{ip} - - [{time}] "GET {path} HTTP/1.1" 404 {bytes_sent} "-" "curl/7.68" directory_scan {count}'
        )
        
        current_time += datetime.timedelta(seconds=1)
    
    return logs, current_time

def request_flood(ip, current_time, count):

    logs = []

    for i in range(100):

        path = random.choice(PATHS_NORMAL)
        time = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        # lots of requests, size may vary moderately
        bytes_sent = random.randint(300, 4000)
        logs.append(
            f'{ip} - - [{time}] "GET {path} HTTP/1.1" 200 {bytes_sent} "-" "curl/7.68" request_flood {count}'
        )

        current_time += datetime.timedelta(milliseconds=200)

    return logs, current_time


def sql_injection_attack(ip, current_time, count):

    logs = []

    for path in SQLI_PATTERNS:

        time = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        # injection attempts often trigger 400/500 responses with moderate payloads
        status = random.choice([400, 500])
        bytes_sent = random.randint(500, 5000)

        logs.append(
            f'{ip} - - [{time}] "GET {path} HTTP/1.1" {status} {bytes_sent} "-" "curl/7.68" sql_injection {count}'
        )

        current_time += datetime.timedelta(seconds=3)

    return logs, current_time


def exfiltration_attack(ip, current_time, count):

    logs = []

    for path in EXFIL_PATHS:

        time = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        # exfil typically involves large responses
        status = 200
        bytes_sent = random.randint(50_000_000, 200_000_000)  # 50–200 MB

        logs.append(
            f'{ip} - - [{time}] "GET {path} HTTP/1.1" {status} {bytes_sent} "-" "curl/7.68" data_exfiltration {count}'
        )

        current_time += datetime.timedelta(seconds=5)

    return logs, current_time


def command_injection_attack(ip, current_time, count):

    logs = []
    max = len(COMMAND_INJECTION_PATTERNS)
    temp = COMMAND_INJECTION_PATTERNS.copy()
    attack_count = random.randint(5,max)

    for i in range(attack_count):
        
        time = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        status = random.choice([500, 403, 200])
        bytes_sent = random.randint(300, 1500)
        agent = random.choice(USER_AGENTS)
        command_choice = random.choice(temp)
        temp.remove(command_choice)  # Ensure we don't reuse the same pattern in this attack session

        logs.append(
            f'{ip} - - [{time}] "GET {command_choice} HTTP/1.1" {status} {bytes_sent} "-" "{agent}" command_injection {count}'
        )

        current_time += datetime.timedelta(seconds = 2)

    return logs, current_time

def generate_logs(
    size=2000,
    users=100,
    gen_access: bool = True,
    gen_auth: bool = False,
    gen_firewall: bool = False,
    ):
    """
    Generate simulated logs.
    """

    if gen_access == False and gen_auth == False and gen_firewall == False:
        print("Critical Error: No log types selected to generate. Exiting...")
        sys.exit(1)

    bf_count = 0
    scan_count = 0
    flood_count = 0
    sqli_count = 0
    exfil_count = 0
    commandi_count = 0

    auth_attack_counters = {
        AUTH_CLASS_SSH_BRUTEFORCE: 0,
        AUTH_CLASS_SSH_USER_ENUM: 0,
        AUTH_CLASS_SUDO_BRUTEFORCE: 0,
    }
    auth_line_count = 0

    profile_counts = {
        "normal": 0,
        "scanner": 0,
        "attacker": 0,
        "compromised": 0,
    }

    log_source_counts = {
        "normal": 0,
        "scanner": 0,
        "attacker": 0,
        "compromised": 0,
    }

    used_ips = []
    ips_that_attacked = {}

    os.makedirs("data", exist_ok=True)

    start_time = datetime.datetime.now()
    current_time = start_time

    user_list = [User(used_ips) for _ in range(users)]

    for user in user_list:
        profile_counts[user.profile] += 1

    access_path = "data/access.log"
    auth_path = "data/auth.log"
    firewall_path = "data/firewall.log"

    access_f_ctx = None
    if gen_access :
        access_f_ctx = open(access_path, "w", encoding="utf-8")
    auth_f_ctx = None
    if gen_auth:
        auth_f_ctx = open(auth_path, "w", encoding="utf-8")
    firewall_f_ctx = None
    if gen_firewall:
        firewall_f_ctx = open(firewall_path, "w", encoding="utf-8")

    try:
        f = access_f_ctx
        auth_f = auth_f_ctx

        for i in range(size):
            if gen_auth:
                # Occasional realistic auth attacks (attacker IPs); otherwise benign bursts.
                if random.random() < 0.012:
                    kind = random.choice(
                        [
                            AUTH_CLASS_SSH_BRUTEFORCE,
                            AUTH_CLASS_SSH_USER_ENUM,
                            AUTH_CLASS_SUDO_BRUTEFORCE,
                        ]
                    )
                    auth_attack_counters[kind] += 1
                    atk_ip = random.choice(IPS_ATTACK)
                    atk_fn = AUTH_ATTACK_FUNCTIONS[kind]
                    auth_lines, current_time = atk_fn(
                        atk_ip, current_time, auth_attack_counters[kind]
                    )
                    for aline in auth_lines:
                        auth_f.write(aline + "\n")
                        auth_line_count += 1
                else:
                    n_pre = random.randint(0, 2)
                    auth_lines, current_time = generate_auth_normal_burst(
                        current_time, n_pre, classification="normal", count=0
                    )
                    for aline in auth_lines:
                        auth_f.write(aline + "\n")
                        auth_line_count += 1

            
            if gen_access:

                user = random.choice(user_list)
                profile = user.profile
                attack_risk = PROFILES[profile]["attack"]
                attack_chance = random.random()

                if attack_chance < attack_risk:
                    if profile == "scanner":
                        logs, current_time = user.perform_attack(
                            "directory_scan",
                            current_time,
                            {"directory_scan": scan_count},
                        )
                        scan_count += 1
                    else:
                        attack_type = user.choose_attack_type()
                        logs, current_time = user.perform_attack(
                            attack_type,
                            current_time,
                            {
                                "brute_force": bf_count,
                                "directory_scan": scan_count,
                                "request_flood": flood_count,
                                "sql_injection": sqli_count,
                                "data_exfiltration": exfil_count,
                                "command_injection": commandi_count,
                            },
                        )

                        if attack_type == "brute_force":
                            bf_count += 1
                        elif attack_type == "request_flood":
                            flood_count += 1
                        elif attack_type == "sql_injection":
                            sqli_count += 1
                        elif attack_type == "data_exfiltration":
                            exfil_count += 1
                        elif attack_type == "command_injection":
                            commandi_count += 1

                    if user.ip not in ips_that_attacked:
                        ips_that_attacked[user.ip] = {
                            "profile": user.profile,
                            "attack_counts": user.attack_counts.copy(),
                            "total_attacks": 0,
                        }

                else:
                    logs, current_time = user.perform_normal_traffic(current_time)

                log_source_counts[user.profile] += 1

                for line in logs:
                    f.write(line + "\n")

                """
                if gen_auth and random.random() < 0.28:
                    line, current_time = generate_auth_normal_event(current_time)
                    auth_f.write(line + "\n")
                """

        for ip, data in ips_that_attacked.items():
            u = next((x for x in user_list if x.ip == ip), None)
            if u:
                data["attack_counts"] = u.attack_counts.copy()
                data["total_attacks"] = sum(u.attack_counts.values())

    finally:
        if access_f_ctx is not None:
            access_f_ctx.close()
        if auth_f_ctx is not None:
            auth_f_ctx.close()
        if firewall_f_ctx is not None:
            firewall_f_ctx.close()

    if gen_auth and sum(auth_attack_counters.values()) > 0:
        print(
            "Auth attack episodes (by label): "
            f"ssh_bruteforce={auth_attack_counters[AUTH_CLASS_SSH_BRUTEFORCE]}, "
            f"ssh_user_enum={auth_attack_counters[AUTH_CLASS_SSH_USER_ENUM]}, "
            f"sudo_bruteforce={auth_attack_counters[AUTH_CLASS_SUDO_BRUTEFORCE]}"
        )

    report_generation_stats(
        bf_count, scan_count, flood_count, sqli_count, exfil_count, commandi_count
    )
    return (
        bf_count,
        scan_count,
        flood_count,
        sqli_count,
        exfil_count,
        commandi_count,
        profile_counts,
        log_source_counts,
        ips_that_attacked,
        dict(auth_attack_counters),
        auth_line_count,
    )


