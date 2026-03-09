import random
import datetime

IPS_NORMAL = [
    "192.168.1.10",
    "192.168.1.20",
    "10.0.0.5",
    "172.16.0.4"
]

IPS_ATTACK = [
    "185.23.54.2",
    "45.33.22.11",
    "91.200.12.55",
    "103.44.12.9"
]

PATHS_NORMAL = [
    "/",
    "/products",
    "/about",
    "/contact",
    "/login",
    "/dashboard"
]

SCAN_PATHS = [
    "/admin",
    "/admin/login",
    "/admin/config",
    "/backup",
    "/.env",
    "/phpmyadmin"
]

USER_AGENTS = [
    "Mozilla/5.0",
    "Chrome/120.0",
    "Safari/17",
    "curl/7.68"
]


def generate_normal_request(time):

    ip = random.choice(IPS_NORMAL)
    path = random.choice(PATHS_NORMAL)
    status = random.choice([200, 200, 200, 404])
    agent = random.choice(USER_AGENTS)

    log = f'{ip} - - [{time}] "GET {path} HTTP/1.1" {status} 1234 "{agent}"'

    return log


def brute_force_attack(ip, current_time):

    logs = []

    for i in range(30):

        time = current_time.strftime("%d/%b/%Y:%H:%M:%S")

        logs.append(
            f'{ip} - - [{time}] "POST /login HTTP/1.1" 401 532 "curl/7.68"'
        )

        current_time += datetime.timedelta(seconds=1)

    return logs


def directory_scan(ip, current_time):

    logs = []

    for path in SCAN_PATHS:

        time = current_time.strftime("%d/%b/%Y:%H:%M:%S")

        logs.append(
            f'{ip} - - [{time}] "GET {path} HTTP/1.1" 404 532 "curl/7.68"'
        )

        current_time += datetime.timedelta(seconds=2)

    return logs

def request_flood(ip, current_time):

    logs = []

    for i in range(150):

        path = random.choice(PATHS_NORMAL)
        time = current_time.strftime("%d/%b/%Y:%H:%M:%S")

        logs.append(
            f'{ip} - - [{time}] "GET {path} HTTP/1.1" 200 1234 "curl/7.68"'
        )

        current_time += datetime.timedelta(milliseconds=200)

    return logs


def generate_logs():

    start_time = datetime.datetime.now()

    current_time = start_time

    with open("data/access.log", "w") as f:

        for i in range(2000):

            # occasional attack events
            attack_chance = random.random()

            if attack_chance < 0.005:

                #print("Generating brute force attack logs...    ")
                logs = brute_force_attack(
                    random.choice(IPS_ATTACK),
                    current_time
                )

                for log in logs:
                    f.write(log + "\n")

            elif attack_chance < 0.01:

                #print("Generating directory scan logs...    ")
                logs = directory_scan(
                    random.choice(IPS_ATTACK),
                    current_time
                )

                for log in logs:
                    f.write(log + "\n")


            elif attack_chance < 0.015:
                
                #print("Generating request flood logs...")
                flood_ip = random.choice(IPS_ATTACK)
                logs = request_flood(
                    flood_ip,
                    current_time
                )

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


if __name__ == "__main__":
    generate_logs()