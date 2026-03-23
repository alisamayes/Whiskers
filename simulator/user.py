import random


class User:
    """Represents a simulated user with behavioral profile and attack capabilities."""

    def __init__(self, used_ips):
        # Assign profile based on realistic distribution
        alignment = random.random()
        if alignment < 0.85:
            self.profile = "normal"
        elif alignment < 0.91:
            self.profile = "scanner"
        elif alignment < 0.96:
            self.profile = "attacker"
        else:
            self.profile = "compromised"
        self.ip = self.get_unused_ip(used_ips)

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

    def get_unused_ip(self, used_ips):
        """Get an unused IP address for this user."""
        if self.profile in ["normal", "compromised"]:
            pool = IPS_NORMAL
        else:
            pool = IPS_ATTACK

        available_ips = [ip for ip in pool if ip not in used_ips]
        if available_ips:
            return random.choice(available_ips)
        else:
            # If all IPs are used, just return a random one
            return random.choice(pool)

# Profile configurations
PROFILES = {
    "normal": {"normal": 0.999, "attack": 0.001},      # 99.9% normal, 0.1% attack
    "compromised": {"normal": 0.9, "attack": 0.1},  # 90% normal, 10% attack
    "scanner": {"normal": 0.3, "attack": 0.7},        # 30% normal, 70% attack
    "attacker": {"normal": 0.05, "attack": 0.95},     # 5% normal, 95% attack
}

# IP pools
IPS_NORMAL = [
    "192.168.1.10", "192.168.1.20", "10.0.0.5", "172.16.0.4",
    "192.168.1.15", "10.0.0.10", "172.16.0.8", "203.0.113.5",
    "192.168.0.100", "10.10.10.1", "192.168.1.25", "10.0.0.15",
    "192.168.1.50", "10.0.0.20", "192.168.1.55", "10.0.0.25",
    "192.168.1.60", "192.168.1.75", "192.168.1.85", "192.168.1.90",
    "192.168.0.120", "192.168.0.130", "10.0.1.5", "10.0.1.10",
    "10.1.0.15", "10.1.0.20", "172.16.1.10", "172.16.1.25",
    "172.17.0.50", "172.18.10.15", "172.20.5.12", "172.21.14.22",
    "172.31.255.10", "198.51.100.23", "203.0.113.25", "203.0.113.45",
    "198.51.100.44", "24.56.112.78", "73.52.220.14", "68.142.15.77",
    "92.40.18.101", "81.2.69.143", "86.15.200.54", "109.150.33.21",
    "151.228.120.88", "5.80.45.12", "37.120.55.102", "62.210.140.33",
    "95.150.75.20", "82.132.215.44", "78.144.12.77"
]

IPS_ATTACK = [
    "185.23.54.2", "45.33.22.11", "91.200.12.55", "103.44.12.9",
    "185.220.101.1", "45.67.89.12", "91.134.56.78", "103.78.90.123",
    "198.51.100.1", "203.0.113.10", "104.244.42.65", "185.199.108.133",
    "1.1.1.1", "8.8.8.8", "97.74.210.1", "82.64.68.1", "97.74.210.2",
    "37.187.129.77", "185.100.87.22", "178.62.31.45", "95.216.41.12",
    "51.38.113.201", "159.89.14.233", "138.68.101.54", "167.71.200.19",
    "46.101.145.87", "89.248.165.195", "80.82.77.139", "185.234.219.5",
    "193.27.228.54", "194.87.105.21", "212.102.35.77", "107.189.12.34",
    "198.98.49.112", "23.129.64.35", "5.188.206.42", "91.92.109.78", 
    "185.38.175.133", "185.81.68.21", "185.255.96.132", "94.102.49.11", 
    "83.97.20.45", "185.217.0.85", "171.25.193.78", "45.133.1.233",
    "176.10.104.243", "149.28.66.101", "66.42.55.72", "172.245.23.177",
    "45.141.84.23"
]