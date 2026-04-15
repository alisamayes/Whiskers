'''
This file will contain the "Generation" page class for Whiskers GUI. It will handle allowing a user to do the generation related
commands via buttons as opposed to the CLI ones
'''

from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QLineEdit
)
from typing import TypedDict
from simulator.log_simulator import generate_logs
from GUI.config import active_dark_green


class _LogToggleEntry(TypedDict):
    state: bool
    button: QPushButton


class GenPage(QWidget):
    def __init__(self, whiskers_agent=None):
        """
        Initialize the Generator Page widget.
        Sets up the page with a range of buttons that allow the user to handle the generation of new simulated log files with buttons as opposed
        to CLI commands, which should be more user friendly
        """
        super().__init__()
        self.whiskers = whiskers_agent

        #Pyqt6 widgets

        self.main_layout = QVBoxLayout()
        # ============================================

        self.gen_box = QVBoxLayout()
        # -----------------------------------------
        self.type_line = QHBoxLayout()
        self.types_label = QLabel("Log Types:")
        self.access_log_button = QPushButton("Access")
        self.access_log_button.clicked.connect(
            lambda: self.toggle_button(self.access_log_button))
        self.auth_log_button = QPushButton("Auth")
        self.auth_log_button.clicked.connect(
            lambda: self.toggle_button(self.auth_log_button))
        self.firewall_log_button = QPushButton("Firewall")
        self.firewall_log_button.clicked.connect(
            lambda: self.toggle_button(self.firewall_log_button))
        
        self.type_line.addWidget(self.types_label)
        self.type_line.addWidget(self.access_log_button)
        self.type_line.addWidget(self.auth_log_button)
        self.type_line.addWidget(self.firewall_log_button)

        self.gen_box.addLayout(self.type_line)
        #--------------------------------------------
        self.additional_options_line = QHBoxLayout()
        self.additional_options_label = QLabel("Additional Options: ")
        self.size_label = QLabel("Size - ")
        self.size_input = QLineEdit("2000")

        self.additional_options_line.addWidget(self.additional_options_label)
        self.additional_options_line.addWidget(self.size_label)
        self.additional_options_line.addWidget(self.size_input)

        self.gen_box.addLayout(self.additional_options_line)
        #--------------------------------------------
        self.generate_button = QPushButton("GENERATE")
        self.generate_button.clicked.connect(self.generate)
        self.gen_box.addWidget(self.generate_button)

        # ============================================

        self.stats_box = QVBoxLayout()
        #--------------------------------------------
        self.true_attack_stats = QLabel("")
        self.actor_labels = QLabel("")
        self.actor_stats = QLabel("")

        self.stats_box.addWidget(self.true_attack_stats)
        self.stats_box.addWidget(self.actor_labels)
        self.stats_box.addWidget(self.actor_stats)


        self.main_layout.addLayout(self.gen_box)
        self.main_layout.addLayout(self.stats_box)
        self.setLayout(self.main_layout)

        #============================================

        # Class variables

        self.log_types: dict[str, _LogToggleEntry] = {
            "Access" : {"state" :False , "button" : self.access_log_button},
            "Auth" : {"state" :False , "button" : self.auth_log_button},
            "Firewall": {"state" :False , "button" : self.firewall_log_button},
        }

        self.toggle_button(self.access_log_button)


    def generate(self):
        """Run log generation with current UI toggles and display results."""
        try:
            size = int(self.size_input.text())
        except ValueError:
            print("Size must be a positive int to run generation")
            return
        gen_access = self.log_types["Access"]["state"]
        gen_auth = self.log_types["Auth"]["state"]
        gen_firewall = self.log_types["Firewall"]["state"]
        engine = getattr(self.window(), "whiskers", None) or self.whiskers
        if engine is not None:
            results = engine.run_generation(
                size=size,
                users=100,
                gen_access=gen_access,
                gen_auth=gen_auth,
                gen_firewall=gen_firewall,
            )
        else:
            # Fallback for standalone page usage outside the main Whiskers window.
            results = generate_logs(
                size,
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
        auth_lines = int(results["auth_line_count"] or 0)
        stats_message = ""

        stats_message += "\n--------------- ACCESS LOG ---------------"
        if gen_access:
            stats_message += "\nBrute-force: " + str(attack_counters.get("access_brute_force", 0))
            stats_message += "\nDirectory scan: " + str(attack_counters.get("access_directory_scan", 0))
            stats_message += "\nRequest flood: " + str(attack_counters.get("access_request_flood", 0))
            stats_message += "\nSQL injection: " + str(attack_counters.get("access_sql_injection", 0))
            stats_message += "\nData exfiltration: " + str(attack_counters.get("access_data_exfiltration", 0))
            stats_message += "\nCommand injection: " + str(attack_counters.get("access_command_injection", 0))
        else:
            stats_message += "\nNot generated."

        stats_message += "\n--------------- AUTH LOG ---------------"
        if gen_auth:
            ssh_bruteforce = int(attack_counters.get("auth_ssh_bruteforce", 0) or 0)
            ssh_user_enum = int(attack_counters.get("auth_ssh_user_enum", 0) or 0)
            sudo_bruteforce = int(attack_counters.get("auth_sudo_bruteforce", 0) or 0)
            privilege_escalation = int(attack_counters.get("auth_privilege_escalation", 0) or 0)
            total_episodes = (
                ssh_bruteforce
                + ssh_user_enum
                + sudo_bruteforce
                + privilege_escalation
            )
            stats_message += "\nSSH brute-force: " + str(ssh_bruteforce)
            stats_message += "\nSSH user enumeration: " + str(ssh_user_enum)
            stats_message += "\nSudo auth failures: " + str(sudo_bruteforce)
            stats_message += "\nPrivilege escalation chain: " + str(privilege_escalation)
            stats_message += "\nTotal auth attack episodes: " + str(total_episodes)
            stats_message += "\nAuth lines written: " + str(auth_lines)
        else:
            stats_message += "\nNot generated."

        stats_message += "\n--------------- FIREWALL LOG ---------------"
        if gen_firewall:
            stats_message += "\nTODO: Implement firewall log generation"
        else:
            stats_message += "\nNot generated."

        self.true_attack_stats.setText(stats_message)
        profile_message = "User distribution and access log line counts:"
        if gen_access:
            profile_message += (
                "\nNormal users: "
                + str(profile_counts["normal"])
                + " users, "
                + str(log_source_counts["normal"])
                + " access lines"
            )
            profile_message += (
                "\nScanner: "
                + str(profile_counts["scanner"])
                + " users, "
                + str(log_source_counts["scanner"])
                + " access lines"
            )
            profile_message += (
                "\nAttacker: "
                + str(profile_counts["attacker"])
                + " users, "
                + str(log_source_counts["attacker"])
                + " access lines"
            )
            profile_message += (
                "\nCompromised: "
                + str(profile_counts["compromised"])
                + " users, "
                + str(log_source_counts["compromised"])
                + " access lines\n"
            )
        else:
            profile_message += (
                "\n(No access log — actor stats reflect user pool only.)\n"
            )
            profile_message += "\nNormal: " + str(profile_counts["normal"]) + " users"
            profile_message += "\nScanner: " + str(profile_counts["scanner"]) + " users"
            profile_message += "\nAttacker: " + str(profile_counts["attacker"]) + " users"
            profile_message += "\nCompromised: " + str(profile_counts["compromised"]) + " users\n"

        self.actor_stats.setText(profile_message)

    def refresh_from_disk_probe(self, w) -> None:
        """Show true attack counts and a short parse summary (same layout style as after Generate)."""
        tc = getattr(w, "true_attack_counts", {}) or {}
        had_access = getattr(w, "_silent_probe_had_access", False)
        had_auth = getattr(w, "_silent_probe_had_auth", False)
        had_fw = getattr(w, "_silent_probe_had_firewall", False)

        stats_message = "\n--------------- ACCESS LOG ---------------"
        if had_access:
            stats_message += "\nBrute-force: " + str(tc.get("access_brute_force", 0))
            stats_message += "\nDirectory scan: " + str(tc.get("access_directory_scan", 0))
            stats_message += "\nRequest flood: " + str(tc.get("access_request_flood", 0))
            stats_message += "\nSQL injection: " + str(tc.get("access_sql_injection", 0))
            stats_message += "\nData exfiltration: " + str(tc.get("access_data_exfiltration", 0))
            stats_message += "\nCommand injection: " + str(tc.get("access_command_injection", 0))
        else:
            stats_message += "Access log: no file found at configured path(s)."

        stats_message += "\n--------------- AUTH LOG ---------------"
        if had_auth:
            stats_message += (
                "\nSSH brute-force: "
                + str(tc.get("auth_ssh_bruteforce", 0))
            )
            stats_message += (
                "\nSSH user enumeration: "
                + str(tc.get("auth_ssh_user_enum", 0))
            )
            stats_message += (
                "\nSudo auth failures: "
                + str(tc.get("auth_sudo_bruteforce", 0))
            )
            stats_message += (
                "\nPrivilege escalation chain: "
                + str(tc.get("auth_privilege_escalation", 0))
            )
        else:
            stats_message += "\nAuth log: no file found at default or configured path(s)."

        stats_message += "\n--------------- FIREWALL LOG ---------------"
        if had_fw:
            stats_message += "\nFirewall log: loaded from disk."
        else:
            stats_message += "\nFirewall log: no file found at default or configured path(s)."

        self.true_attack_stats.setText(stats_message)

        df = getattr(w, "df", None)
        pc = getattr(w, "profile_counts", {}) or {}
        lsc = getattr(w, "log_source_counts", {}) or {}
        sim_profiles = sum(int(pc.get(k, 0) or 0) for k in ("normal", "scanner", "attacker", "compromised"))

        if sim_profiles > 0:
            profile_message = "User distribution and access log line counts (from last simulation):"
            profile_message += (
                "\nNormal users: "
                + str(pc.get("normal", 0))
                + " users, "
                + str(lsc.get("normal", 0))
                + " access lines"
            )
            profile_message += (
                "\nScanner: "
                + str(pc.get("scanner", 0))
                + " users, "
                + str(lsc.get("scanner", 0))
                + " access lines"
            )
            profile_message += (
                "\nAttacker: "
                + str(pc.get("attacker", 0))
                + " users, "
                + str(lsc.get("attacker", 0))
                + " access lines"
            )
            profile_message += (
                "\nCompromised: "
                + str(pc.get("compromised", 0))
                + " users, "
                + str(lsc.get("compromised", 0))
                + " access lines\n"
            )
            self.actor_stats.setText(profile_message)
        elif df is not None and not df.empty and "log_source" in df.columns:
            vc = df["log_source"].value_counts().to_string()
            n = int(df.shape[0])
            self.actor_stats.setText(
                f"Parsed from disk: {n} merged row(s).\nRows by log_source:\n{vc}"
            )
        else:
            self.actor_stats.setText(
                "No merged dataframe yet (no log files found or empty parse)."
            )

    def toggle_button(self, button: QPushButton):
        """Toggle a log-type button state and update its visual style."""
        text = button.text()
        entry = self.log_types[text]

        entry["state"] = not entry["state"]
        if entry["state"]:
            entry["button"].setStyleSheet(f"color: {active_dark_green};")
        else:
            entry["button"].setStyleSheet("")


    