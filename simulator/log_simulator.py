import os
import random
import datetime
import sys

from simulator.user import User, PROFILES, IPS_ATTACK
from simulator.access_log_simulator import (
    generate_normal_request,
    brute_force_attack,
    directory_scan,
    request_flood,
    sql_injection_attack,
    exfiltration_attack,
    command_injection_attack,
)
from simulator.auth_log_simulator import (
    auth_ssh_bruteforce_attack,
    auth_ssh_user_enum_attack,
    auth_sudo_bruteforce_attack,
    auth_privilege_escalation_attack,
    generate_auth_normal_event,
)
from analysis.stats import report_generation_stats

def generate_logs(
    size=2000,
    users=100,
    gen_access: bool = True,
    gen_auth: bool = False,
    gen_firewall: bool = False,
    ):
    """
    Generate access/auth/firewall log files and return generation stats.

    Returns a dictionary with keys:
      * attack_counters
      * profile_counts
      * log_source_counts
      * auth_log_source_counts
      * access_instance_count
      * access_line_count
      * auth_instance_count
      * auth_line_count
      * ips_that_attacked
    """

    if gen_access == False and gen_auth == False and gen_firewall == False:
        print("Critical Error: No log types selected to generate. Exiting...")
        sys.exit(1)

    attack_counters = {
        "access_brute_force": 0,
        "access_directory_scan": 0,
        "access_request_flood": 0,
        "access_sql_injection": 0,
        "access_data_exfiltration": 0,
        "access_command_injection": 0,
        "auth_ssh_bruteforce": 0,
        "auth_ssh_user_enum": 0,
        "auth_sudo_bruteforce": 0,
        "auth_privilege_escalation": 0,
    }

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
    auth_log_source_counts = {
        "normal": 0,
        "scanner": 0,
        "attacker": 0,
        "compromised": 0,
    }

    access_line_count = 0
    auth_line_count = 0

    used_ips: list[str] = []
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
                assert auth_f is not None
                # One auth instance per loop: either one attack episode or one normal event.
                if random.random() < 0.016:
                    kind = random.choice(["auth_ssh_bruteforce", "auth_ssh_user_enum", "auth_sudo_bruteforce", "auth_privilege_escalation"])
                    attack_counters[kind] += 1
                    atk_ip = random.choice(IPS_ATTACK)
                    if kind == "auth_ssh_bruteforce":
                        atk_fn = auth_ssh_bruteforce_attack
                    elif kind == "auth_ssh_user_enum":
                        atk_fn = auth_ssh_user_enum_attack
                    elif kind == "auth_sudo_bruteforce":
                        atk_fn = auth_sudo_bruteforce_attack
                    elif kind == "auth_privilege_escalation":
                        atk_fn = auth_privilege_escalation_attack
                    auth_lines, current_time = atk_fn(
                        atk_ip, current_time, attack_counters[kind]
                    )
                    if kind in ("auth_sudo_bruteforce", "auth_privilege_escalation"):
                        auth_actor = "compromised"
                    else:
                        auth_actor = "attacker"
                    for aline in auth_lines:
                        auth_f.write(aline + "\n")
                        auth_line_count += 1
                        auth_log_source_counts[auth_actor] += 1
                else:
                    line, current_time = generate_auth_normal_event(
                        current_time, classification="normal", count=0
                    )
                    auth_f.write(line + "\n")
                    auth_line_count += 1
                    auth_log_source_counts["normal"] += 1

            
            if gen_access:
                assert f is not None

                user = random.choice(user_list)
                profile = user.profile
                attack_risk = PROFILES[profile]["attack"]
                attack_chance = random.random()

                if attack_chance < attack_risk:
                    if profile == "scanner":
                        logs, current_time = user.perform_attack(
                            "access_directory_scan",
                            current_time,
                            attack_counters,
                        )
                    else:
                        attack_type = user.choose_attack_type()
                        logs, current_time = user.perform_attack(
                            attack_type,
                            current_time,
                            attack_counters,
                        )

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
                    access_line_count += 1

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


    return {
        "attack_counters": attack_counters,
        "profile_counts": profile_counts,
        "log_source_counts": log_source_counts,
        "auth_log_source_counts": auth_log_source_counts,
        "access_instance_count": size if gen_access else 0,
        "access_line_count": access_line_count,
        "auth_instance_count": size if gen_auth else 0,
        "ips_that_attacked": ips_that_attacked,
        "auth_line_count": auth_line_count,
    }


