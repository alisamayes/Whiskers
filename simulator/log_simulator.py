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

    log = f'{ip} - - [{time}] "GET {path} HTTP/1.1" {status} 1234 "{agent}" normal'

    return log


def brute_force_attack(ip, current_time, count):

    logs = []

    for i in range(5,40):

        time = current_time.strftime("%d/%b/%Y:%H:%M:%S")

        logs.append(
            f'{ip} - - [{time}] "POST /login HTTP/1.1" 401 532 "curl/7.68" brute_force {count}'
        )

        current_time += datetime.timedelta(seconds=1)

    return logs


def directory_scan(ip, current_time, count):

    logs = []

    for path in SCAN_PATHS:

        time = current_time.strftime("%d/%b/%Y:%H:%M:%S")

        logs.append(
            f'{ip} - - [{time}] "GET {path} HTTP/1.1" 404 532 "curl/7.68" directory_scan {count}'
        )
        
        current_time += datetime.timedelta(seconds=2)
    
    return logs

def request_flood(ip, current_time, count):

    logs = []

    for i in range(150):

        path = random.choice(PATHS_NORMAL)
        time = current_time.strftime("%d/%b/%Y:%H:%M:%S")

        logs.append(
            f'{ip} - - [{time}] "GET {path} HTTP/1.1" 200 1234 "curl/7.68" request_flood {count}'
        )

        current_time += datetime.timedelta(milliseconds=200)

    return logs


def generate_logs(size=2000):

    bf_count = 0
    scan_count = 0
    flood_count = 0

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
            
            else:

                # print("Generating normal logs...    ")
                time_str = current_time.strftime("%d/%b/%Y:%H:%M:%S")

                log = generate_normal_request(time_str)

                f.write(log + "\n")

            current_time += datetime.timedelta(
                seconds=random.randint(1,5)
            )

    return bf_count, scan_count, flood_count


if __name__ == "__main__":
    generate_logs()
