import datetime
import os
import random
import sys

from analysis.stats import report_generation_stats
from simulator.access_log_simulator import (
    brute_force_attack,
    command_injection_attack,
    directory_scan,
    exfiltration_attack,
    generate_normal_request,
    request_flood,
    sql_injection_attack,
)
from simulator.auth_log_simulator import (
    auth_privilege_escalation_attack,
    auth_ssh_bruteforce_attack,
    auth_ssh_user_enum_attack,
    auth_sudo_bruteforce_attack,
    generate_auth_normal_event,
)
from simulator.firewall_log_simulator import (
    firewall_blocked_ssh_bruteforce,
    firewall_denied_egress_exfiltration,
    firewall_port_scan_attack,
    firewall_syn_flood_attack,
    generate_firewall_normal_event,
)
from simulator.user import IPS_ATTACK, PROFILES, User


def generate_logs(
    sizes=[2000, 2000, 2000],
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
      * access_log_source_counts
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
        "firewall_port_scan": 0,
        "firewall_blocked_ssh_bruteforce": 0,
        "firewall_syn_flood": 0,
        "firewall_denied_egress_exfiltration": 0,
    }

    profile_counts = {
        "normal": 0,
        "scanner": 0,
        "attacker": 0,
        "compromised": 0,
    }

    access_log_source_counts = {
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
    firewall_line_count = 0

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
    if gen_access:
        access_f_ctx = open(access_path, "w", encoding="utf-8")
    auth_f_ctx = None
    if gen_auth:
        auth_f_ctx = open(auth_path, "w", encoding="utf-8")
    firewall_f_ctx = None
    if gen_firewall:
        firewall_f_ctx = open(firewall_path, "w", encoding="utf-8")

    try:
        all_logs = []
        remaining = sizes.copy()
        total_logs = sum(sizes)

        for _ in range(total_logs):
            available_types = [
                i
                for i in range(3)
                if remaining[i] > 0
                and (gen_access if i == 0 else gen_auth if i == 1 else gen_firewall)
            ]
            if not available_types:
                break
            type_idx = random.choice(available_types)

            if type_idx == 0:  # access
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

                access_log_source_counts[user.profile] += 1

                for line in logs:
                    all_logs.append(("access", line))
                    access_line_count += 1

                remaining[0] -= 1

            elif type_idx == 1:  # auth
                if random.random() < 0.016:
                    kind = random.choice(
                        [
                            "auth_ssh_bruteforce",
                            "auth_ssh_user_enum",
                            "auth_sudo_bruteforce",
                            "auth_privilege_escalation",
                        ]
                    )
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
                        all_logs.append(("auth", aline))
                        auth_line_count += 1
                        auth_log_source_counts[auth_actor] += 1
                else:
                    line, current_time = generate_auth_normal_event(
                        current_time, classification="normal", count=0
                    )
                    all_logs.append(("auth", line))
                    auth_line_count += 1
                    auth_log_source_counts["normal"] += 1

                remaining[1] -= 1

            elif type_idx == 2:  # firewall
                if random.random() < 0.02:
                    attack_kind = random.choice(
                        [
                            "firewall_port_scan",
                            "firewall_blocked_ssh_bruteforce",
                            "firewall_syn_flood",
                            "firewall_denied_egress_exfiltration",
                        ]
                    )
                    attack_counters[attack_kind] += 1
                    atk_ip = random.choice(IPS_ATTACK)
                    if attack_kind == "firewall_port_scan":
                        attack_fn = firewall_port_scan_attack
                    elif attack_kind == "firewall_blocked_ssh_bruteforce":
                        attack_fn = firewall_blocked_ssh_bruteforce
                    elif attack_kind == "firewall_syn_flood":
                        attack_fn = firewall_syn_flood_attack
                    else:
                        attack_fn = firewall_denied_egress_exfiltration

                    fw_lines, current_time = attack_fn(
                        atk_ip, current_time, attack_counters[attack_kind]
                    )
                    for fline in fw_lines:
                        all_logs.append(("firewall", fline))
                        firewall_line_count += 1
                else:
                    line, current_time = generate_firewall_normal_event(current_time)
                    all_logs.append(("firewall", line))
                    firewall_line_count += 1

                remaining[2] -= 1

        for ip, data in ips_that_attacked.items():
            u = next((x for x in user_list if x.ip == ip), None)
            if u:
                data["attack_counts"] = u.attack_counts.copy()
                data["total_attacks"] = sum(u.attack_counts.values())

        # Write logs to files in the order they were generated (which is chronological)
        for log_type, line in all_logs:
            if log_type == "access" and access_f_ctx:
                access_f_ctx.write(line + "\n")
            elif log_type == "auth" and auth_f_ctx:
                auth_f_ctx.write(line + "\n")
            elif log_type == "firewall" and firewall_f_ctx:
                firewall_f_ctx.write(line + "\n")

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
        "access_log_source_counts": access_log_source_counts,
        "auth_log_source_counts": auth_log_source_counts,
        "access_instance_count": sizes[0] if gen_access else 0,
        "access_line_count": access_line_count,
        "auth_instance_count": sizes[1] if gen_auth else 0,
        "ips_that_attacked": ips_that_attacked,
        "auth_line_count": auth_line_count,
        "firewall_instance_count": sizes[2] if gen_firewall else 0,
        "firewall_line_count": firewall_line_count,
    }
