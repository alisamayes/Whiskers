import random
import datetime

IPS_NORMAL = [
    "192.168.1.10",
    "192.168.1.20",
    "10.0.0.5",
    "172.16.0.4",
    "192.168.1.15",
    "10.0.0.10",
    "172.16.0.8",
    "203.0.113.5",
    "192.168.0.100",
    "10.10.10.1"
]

IPS_ATTACK = [
    "185.23.54.2",
    "45.33.22.11",
    "91.200.12.55",
    "103.44.12.9",
    "185.220.101.1",
    "45.67.89.12",
    "91.134.56.78",
    "103.78.90.123",
    "198.51.100.1",
    "203.0.113.10",
    "104.244.42.65",
    "185.199.108.133"
]

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


def generate_logs(size=2000):

    bf_count = 0
    scan_count = 0
    flood_count = 0
    sqli_count = 0
    exfil_count = 0

    start_time = datetime.datetime.now()

    current_time = start_time

    with open("data/access.log", "w") as f:

        for i in range(size):

            # occasional attack events
            attack_chance = random.random()

            if attack_chance < 0.005:

                #print("Generating brute force attack logs...    ")
                logs = brute_force_attack(
                    random.choice(IPS_ATTACK),
                    current_time,
                    bf_count
                )
                bf_count += 1

                for log in logs:
                    f.write(log + "\n")

            elif attack_chance < 0.01:

                #print("Generating directory scan logs...    ")
                logs = directory_scan(
                    random.choice(IPS_ATTACK),
                    current_time,
                    scan_count
                )
                scan_count += 1

                for log in logs:
                    f.write(log + "\n")


            elif attack_chance < 0.015:
                
                #print("Generating request flood logs...")
                flood_ip = random.choice(IPS_ATTACK)
                logs = request_flood(
                    flood_ip,
                    current_time,
                    flood_count
                )
                flood_count += 1

                for log in logs:
                    f.write(log + "\n")

            elif attack_chance < 0.02:

                # SQL injection attempts
                logs = sql_injection_attack(
                    random.choice(IPS_ATTACK),
                    current_time,
                    sqli_count
                )
                sqli_count += 1

                for log in logs:
                    f.write(log + "\n")

            elif attack_chance < 0.025:

                # data exfiltration attempts
                logs = exfiltration_attack(
                    random.choice(IPS_ATTACK),
                    current_time,
                    exfil_count,
                )
                exfil_count += 1

                for log in logs:
                    f.write(log + "\n")
            
            else:

                # print("Generating normal logs...    ")
                time_str = current_time.strftime("%d/%b/%Y:%H:%M:%S")

                log = generate_normal_request(time_str)

                f.write(log + "\n")

            current_time += datetime.timedelta(
                seconds=random.randint(1,5)
            )

    return bf_count, scan_count, flood_count, sqli_count, exfil_count


if __name__ == "__main__":
    generate_logs()
