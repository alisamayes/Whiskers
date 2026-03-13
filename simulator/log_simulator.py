import random
import datetime

from simulator.user import User, PROFILES, IPS_NORMAL


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
    "/search?q=\" OR \"1\"=\"1",
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




def generate_normal_request(time):

    ip = random.choice(IPS_NORMAL)
    path = random.choice(PATHS_NORMAL)
    status = random.choice([200, 200, 200, 200, 200, 404])
    agent = random.choice(USER_AGENTS)
    # simulate different response sizes (in bytes)
    bytes_sent = random.randint(300, 5000)

    log = f'{ip} - - [{time}] "GET {path} HTTP/1.1" {status} {bytes_sent} "{agent}" normal'

    return log


def brute_force_attack(ip, current_time, count):

    logs = []

    for i in range(5,40):

        time = current_time.strftime("%d/%b/%Y:%H:%M:%S")

        # failed login responses are usually small-ish
        bytes_sent = random.randint(300, 1500)
        logs.append(
            f'{ip} - - [{time}] "POST /login HTTP/1.1" 401 {bytes_sent} "curl/7.68" brute_force {count}'
        )

        current_time += datetime.timedelta(seconds=1)

    return logs


def directory_scan(ip, current_time, count):

    logs = []

    for path in SCAN_PATHS:

        time = current_time.strftime("%d/%b/%Y:%H:%M:%S")

        bytes_sent = random.randint(300, 2000)
        logs.append(
            f'{ip} - - [{time}] "GET {path} HTTP/1.1" 404 {bytes_sent} "curl/7.68" directory_scan {count}'
        )
        
        current_time += datetime.timedelta(seconds=2)
    
    return logs

def request_flood(ip, current_time, count):

    logs = []

    for i in range(150):

        path = random.choice(PATHS_NORMAL)
        time = current_time.strftime("%d/%b/%Y:%H:%M:%S")
        # lots of requests, size may vary moderately
        bytes_sent = random.randint(300, 4000)
        logs.append(
            f'{ip} - - [{time}] "GET {path} HTTP/1.1" 200 {bytes_sent} "curl/7.68" request_flood {count}'
        )

        current_time += datetime.timedelta(milliseconds=200)

    return logs


def sql_injection_attack(ip, current_time, count):

    logs = []

    for path in SQLI_PATTERNS:

        time = current_time.strftime("%d/%b/%Y:%H:%M:%S")
        # injection attempts often trigger 400/500 responses with moderate payloads
        status = random.choice([400, 500])
        bytes_sent = random.randint(500, 5000)

        logs.append(
            f'{ip} - - [{time}] "GET {path} HTTP/1.1" {status} {bytes_sent} "curl/7.68" sql_injection {count}'
        )

        current_time += datetime.timedelta(seconds=3)

    return logs


def exfiltration_attack(ip, current_time, count):

    logs = []

    for path in EXFIL_PATHS:

        time = current_time.strftime("%d/%b/%Y:%H:%M:%S")
        # exfil typically involves large responses
        status = 200
        bytes_sent = random.randint(50_000_000, 200_000_000)  # 50–200 MB

        logs.append(
            f'{ip} - - [{time}] "GET {path} HTTP/1.1" {status} {bytes_sent} "curl/7.68" data_exfiltration {count}'
        )

        current_time += datetime.timedelta(seconds=5)

    return logs


def generate_logs(size=2000, users = 100):

    bf_count = 0
    scan_count = 0
    flood_count = 0
    sqli_count = 0
    exfil_count = 0

    users = [User() for _ in range(users)]

    start_time = datetime.datetime.now()
    current_time = start_time

    with open("data/access.log", "w") as f:

        for i in range(size):
            # Pick a random user and use their profile probabilities
            user = random.choice(users)
            profile = user.profile
            attack_risk = PROFILES[profile]["attack"]

            # Decide whether this log line is an attack or normal traffic
            attack_chance = random.random()

            if attack_chance < attack_risk:
                # User performs an attack
                if profile == "scanner":
                    logs = user.perform_attack(
                        "directory_scan",
                        current_time,
                        {"directory_scan": scan_count},
                    )
                    scan_count += 1
                else:
                    attack_type = user.choose_attack_type()
                    logs = user.perform_attack(
                        attack_type,
                        current_time,
                        {
                            "brute_force": bf_count,
                            "directory_scan": scan_count,
                            "request_flood": flood_count,
                            "sql_injection": sqli_count,
                            "data_exfiltration": exfil_count,
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
            else:
                # Normal traffic for this user
                logs = user.perform_normal_traffic(current_time)

            # Ensure each log entry is written on its own line
            for line in logs:
                f.write(line + "\n")
        

            

    report_generation_stats(bf_count, scan_count, flood_count, sqli_count, exfil_count)
    return bf_count, scan_count, flood_count, sqli_count, exfil_count

def report_generation_stats(bf, sc, fl, sqli, exfil):
    print(
        "Generated logs with "
        f"{bf} brute force attacks, "
        f"{sc} directory scans, "
        f"{fl} request floods, "
        f"{sqli} SQL injection attacks, and "
        f"{exfil} data exfiltration attempts."
    )
