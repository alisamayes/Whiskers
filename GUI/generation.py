"""
This file will contain the "Generation" page class for Whiskers GUI. It will handle allowing a user to do the generation related
commands via buttons as opposed to the CLI ones
"""

from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from GUI.log_type_selector import LogTypeSelector
from simulator.log_simulator import generate_logs


class GenPage(QWidget):
    def __init__(self, whiskers_agent=None):
        """
        Initialize the Generator Page widget.
        Sets up the page with a range of buttons that allow the user to handle the generation of new simulated log files with buttons as opposed
        to CLI commands, which should be more user friendly
        """
        super().__init__()
        self.whiskers = whiskers_agent

        # Pyqt6 widgets

        self.main_layout = QVBoxLayout()
        # ============================================

        self.gen_box = QVBoxLayout()
        # -----------------------------------------
        self.log_type_selector = LogTypeSelector(default_access=True)
        self.gen_box.addWidget(self.log_type_selector)
        # --------------------------------------------
        self.additional_options_line = QHBoxLayout()
        self.additional_options_label = QLabel("Additional Options: ")
        self.size_label = QLabel("Size - ")
        self.access_size_input = QLineEdit("1000")
        self.auth_size_input = QLineEdit("1000")
        self.firewall_size_input = QLineEdit("1000")

        self.additional_options_line.addWidget(self.additional_options_label)
        self.additional_options_line.addWidget(self.size_label)
        self.additional_options_line.addWidget(self.access_size_input)
        self.additional_options_line.addWidget(self.auth_size_input)
        self.additional_options_line.addWidget(self.firewall_size_input)

        self.gen_box.addLayout(self.additional_options_line)
        # --------------------------------------------
        self.generate_button = QPushButton("GENERATE")
        self.generate_button.clicked.connect(self.generate)
        self.gen_box.addWidget(self.generate_button)
        # Keep controls compact at the top of the page.
        self.gen_box.addStretch(1)

        # ============================================

        self.stats_box = QVBoxLayout()
        # --------------------------------------------
        self.true_attack_stats = QLabel("")
        self.actor_labels = QLabel("")
        self.actor_stats = QLabel("")

        self.stats_box.addWidget(self.true_attack_stats)
        self.stats_box.addWidget(self.actor_labels)
        self.stats_box.addWidget(self.actor_stats)

        self.main_layout.addLayout(self.gen_box, stretch=0)
        self.main_layout.addLayout(self.stats_box, stretch=1)
        self.setLayout(self.main_layout)

        # ============================================

        # Class variables

    def generate(self):
        """Run log generation with current UI toggles and display results."""
        states = self.log_type_selector.selected_states()
        gen_access = states["Access"]
        gen_auth = states["Auth"]
        gen_firewall = states["Firewall"]
        access_size = 2000
        auth_size = 2000
        firewall_size = 2000

        if not any((gen_access, gen_auth, gen_firewall)):
            print("Select at least one log type before generating.")
            return

        if gen_access:
            try:
                access_size = int(self.access_size_input.text())
            except ValueError:
                print("Access size must be a positive int to run generation")
                return
            if access_size <= 0:
                print("Access size must be a positive int to run generation")
                return
        if gen_auth:
            try:
                auth_size = int(self.auth_size_input.text())
            except ValueError:
                print("Auth size must be a positive int to run generation")
                return
            if auth_size <= 0:
                print("Auth size must be a positive int to run generation")
                return
        if gen_firewall:
            try:
                firewall_size = int(self.firewall_size_input.text())
            except ValueError:
                print("Firewall size must be a positive int to run generation")
                return
            if firewall_size <= 0:
                print("Firewall size must be a positive int to run generation")
                return

        sizes = [access_size, auth_size, firewall_size]

        engine = getattr(self.window(), "whiskers", None) or self.whiskers
        if engine is not None:
            results = engine.run_generation(
                sizes=sizes,
                users=100,
                gen_access=gen_access,
                gen_auth=gen_auth,
                gen_firewall=gen_firewall,
            )
        else:
            # Fallback for standalone page usage outside the main Whiskers window.
            results = generate_logs(
                sizes,
                100,
                gen_access,
                gen_auth,
                gen_firewall,
            )
        self.update_stats(
            results,
            gen_access=gen_access,
            gen_auth=gen_auth,
            gen_firewall=gen_firewall,
        )

    def update_stats(
        self,
        results,
        *,
        gen_access: bool = True,
        gen_auth: bool = False,
        gen_firewall: bool = False,
    ):
        """Render generation summary counts for selected log sources."""
        attack_counters = results["attack_counters"]
        profile_counts = results["profile_counts"]
        log_source_counts = results["log_source_counts"]
        auth_log_source_counts = results.get("auth_log_source_counts", {})
        access_instances = int(results.get("access_instance_count", 0) or 0)
        access_lines = int(results.get("access_line_count", 0) or 0)
        auth_instances = int(results.get("auth_instance_count", 0) or 0)
        auth_lines = int(results["auth_line_count"] or 0)
        firewall_instances = int(results.get("firewall_instance_count", 0) or 0)
        firewall_lines = int(results.get("firewall_line_count", 0) or 0)
        stats_message = ""

        stats_message += "\n--------------- ACCESS LOG ---------------"
        if gen_access:
            total_access_attacks = (
                attack_counters.get("access_brute_force", 0)
                + attack_counters.get("access_directory_scan", 0)
                + attack_counters.get("access_request_flood", 0)
                + attack_counters.get("access_sql_injection", 0)
                + attack_counters.get("access_data_exfiltration", 0)
                + attack_counters.get("access_command_injection", 0)
            )
            stats_message += "\nBrute-force: " + str(
                attack_counters.get("access_brute_force", 0)
            )
            stats_message += "\nDirectory scan: " + str(
                attack_counters.get("access_directory_scan", 0)
            )
            stats_message += "\nRequest flood: " + str(
                attack_counters.get("access_request_flood", 0)
            )
            stats_message += "\nSQL injection: " + str(
                attack_counters.get("access_sql_injection", 0)
            )
            stats_message += "\nData exfiltration: " + str(
                attack_counters.get("access_data_exfiltration", 0)
            )
            stats_message += "\nCommand injection: " + str(
                attack_counters.get("access_command_injection", 0)
            )
            stats_message += "\nTotal attacks detected in access log: " + str(
                total_access_attacks
            )
        else:
            stats_message += "\nNot generated."

        stats_message += "\n--------------- AUTH LOG ---------------"
        if gen_auth:
            ssh_bruteforce = int(attack_counters.get("auth_ssh_bruteforce", 0) or 0)
            ssh_user_enum = int(attack_counters.get("auth_ssh_user_enum", 0) or 0)
            sudo_bruteforce = int(attack_counters.get("auth_sudo_bruteforce", 0) or 0)
            privilege_escalation = int(
                attack_counters.get("auth_privilege_escalation", 0) or 0
            )
            total_auth_attacks = (
                ssh_bruteforce + ssh_user_enum + sudo_bruteforce + privilege_escalation
            )
            stats_message += "\nSSH brute-force: " + str(ssh_bruteforce)
            stats_message += "\nSSH user enumeration: " + str(ssh_user_enum)
            stats_message += "\nSudo auth failures: " + str(sudo_bruteforce)
            stats_message += "\nPrivilege escalation chain: " + str(
                privilege_escalation
            )
            stats_message += "\nTotal attacks detected in auth log: " + str(
                total_auth_attacks
            )
        else:
            stats_message += "\nNot generated."

        stats_message += "\n--------------- FIREWALL LOG ---------------"
        if gen_firewall:
            fw_port_scan = int(attack_counters.get("firewall_port_scan", 0) or 0)
            fw_ssh_bf = int(
                attack_counters.get("firewall_blocked_ssh_bruteforce", 0) or 0
            )
            fw_syn_flood = int(attack_counters.get("firewall_syn_flood", 0) or 0)
            fw_egress = int(
                attack_counters.get("firewall_denied_egress_exfiltration", 0) or 0
            )
            fw_total = fw_port_scan + fw_ssh_bf + fw_syn_flood + fw_egress
            stats_message += "\nBlocked port scan episodes: " + str(fw_port_scan)
            stats_message += "\nBlocked SSH bruteforce episodes: " + str(fw_ssh_bf)
            stats_message += "\nSYN flood episodes: " + str(fw_syn_flood)
            stats_message += "\nDenied egress exfiltration episodes: " + str(fw_egress)
            stats_message += "\nTotal firewall attack episodes generated: " + str(
                fw_total
            )
        else:
            stats_message += "\nNot generated."

        self.true_attack_stats.setText(stats_message)
        profile_message = "Generated file totals:"
        if gen_access:
            profile_message += (
                "\nAccess log: "
                + str(access_instances)
                + " instances, "
                + str(access_lines)
                + " lines"
            )
        if gen_auth:
            profile_message += (
                "\nAuth log: "
                + str(auth_instances)
                + " instances, "
                + str(auth_lines)
                + " lines"
            )
        if gen_firewall:
            profile_message += (
                "\nFirewall log: "
                + str(firewall_instances)
                + " instances, "
                + str(firewall_lines)
                + " lines"
            )

        profile_message += (
            "\n\nUser distribution and generated log line counts by actor:"
        )
        roles = ("normal", "scanner", "attacker", "compromised")
        for role in roles:
            users_count = int(profile_counts.get(role, 0) or 0)
            access_count = int(log_source_counts.get(role, 0) or 0) if gen_access else 0
            auth_count = (
                int(auth_log_source_counts.get(role, 0) or 0) if gen_auth else 0
            )
            label = role.capitalize()
            profile_message += f"\n{label}: {users_count} users, {access_count} access lines, {auth_count} auth lines"

        profile_message += (
            "\n\n(Actor rows show generated lines by actor for each log type.)"
        )

        self.actor_stats.setText(profile_message)

