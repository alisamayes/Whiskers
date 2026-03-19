import random


class User:
    """Represents a simulated user with behavioral profile and attack capabilities."""

    def __init__(self):
        # Assign profile based on realistic distribution
        alignment = random.random()
        if alignment < 0.85:
            self.profile = "normal"
            self.ip = random.choice(IPS_NORMAL)
        elif alignment < 0.91:
            self.profile = "scanner"
            self.ip = random.choice(IPS_ATTACK)
        elif alignment < 0.96:
            self.profile = "attacker"
            self.ip = random.choice(IPS_ATTACK)
        else:
            self.profile = "compromised"
            self.ip = random.choice(IPS_NORMAL)

        # Profile-specific behavior probabilities
        self.behavior_probs = PROFILES[self.profile]

        # Track attack counts for this user
        self.attack_counts = {
            "brute_force": 0,
            "directory_scan": 0,
            "request_flood": 0,
            "sql_injection": 0,
            "data_exfiltration": 0
        }



    def decide_action(self):
        """Decide whether to perform normal traffic or an attack. Previous method of attackers always attacking was unrealistic."""
        return "attack" if random.random() < self.behavior_probs["attack"] else "normal"

    def choose_attack_type(self):
        """Choose which attack to perform based on profile capabilities."""
        if self.profile == "scanner":
            # Scanners only do directory scans
            return "directory_scan"
        elif self.profile in ["attacker", "compromised", "normal"]:
            # Attackers and compromised users can do any attack
            attack_weights = {
                "brute_force": 0.3,
                "directory_scan": 0.1,
                "request_flood": 0.2,
                "sql_injection": 0.2,
                "data_exfiltration": 0.2
            }
            attacks = list(attack_weights.keys())
            weights = list(attack_weights.values())
            return random.choices(attacks, weights=weights)[0]
        else:
            # Normal users don't attack
            return None

    def perform_attack(self, attack_type, current_time, global_counters):
        """Perform an attack and update counters."""
        from simulator.log_simulator import (
            brute_force_attack, directory_scan, request_flood,
            sql_injection_attack, exfiltration_attack
        )

        attack_functions = {
            "brute_force": brute_force_attack,
            "directory_scan": directory_scan,
            "request_flood": request_flood,
            "sql_injection": sql_injection_attack,
            "data_exfiltration": exfiltration_attack
        }

        if attack_type in attack_functions:
             # Get the attack logs and updated time
            logs, new_time = attack_functions[attack_type](self.ip, current_time, global_counters[attack_type])

            # Update counters
            self.attack_counts[attack_type] += 1
            global_counters[attack_type] += 1

            return logs, new_time
        return [], current_time

    def perform_normal_traffic(self, current_time):
        """Generate normal traffic for this user and advance time."""
        from simulator.log_simulator import generate_normal_request
        log, new_time = generate_normal_request(current_time)
        return [log], new_time


# Profile configurations
PROFILES = {
    "normal": {"normal": 0.999, "attack": 0.001},      # 99.9% normal, 0.1% attack
    "compromised": {"normal": 0.95, "attack": 0.05},  # 95% normal, 5% attack
    "scanner": {"normal": 0.3, "attack": 0.7},        # 30% normal, 70% attack
    "attacker": {"normal": 0.05, "attack": 0.95},     # 5% normal, 95% attack
}

# IP pools
IPS_NORMAL = [
    "192.168.1.10", "192.168.1.20", "10.0.0.5", "172.16.0.4",
    "192.168.1.15", "10.0.0.10", "172.16.0.8", "203.0.113.5",
    "192.168.0.100", "10.10.10.1", "192.168.1.25", "10.0.0.15",
    "192.168.1.50", "10.0.0.20", "192.168.1.55", "10.0.0.25"
]

IPS_ATTACK = [
    "185.23.54.2", "45.33.22.11", "91.200.12.55", "103.44.12.9",
    "185.220.101.1", "45.67.89.12", "91.134.56.78", "103.78.90.123",
    "198.51.100.1", "203.0.113.10", "104.244.42.65", "185.199.108.133",
    "1.1.1.1", "8.8.8.8", "97.74.210.1", "82.64.68.1", "97.74.210.2"
]