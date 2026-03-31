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
from simulator.log_simulator import generate_logs
from GUI.config import active_dark_green



class GenPage(QWidget):
    def __init__(self):
        """
        Initialize the Generator Page widget.
        Sets up the page with a range of buttons that allow the user to handle the generation of new simulated log files with buttons as opposed
        to CLI commands, which should be more user friendly
        """
        super().__init__()

        #Pyqt6 widgets

        self.layout = QVBoxLayout()
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
        self.true_attack_label = QLabel("Attack data from latest run:")
        self.true_attack_stats = QLabel(": : : :")
        self.actor_labels = QLabel("Actor Statistics:")
        self.actor_stats = QLabel(": : : :")

        self.stats_box.addWidget(self.true_attack_label)
        self.stats_box.addWidget(self.true_attack_stats)
        self.stats_box.addWidget(self.actor_labels)
        self.stats_box.addWidget(self.actor_stats)


        self.layout.addLayout(self.gen_box)
        self.layout.addLayout(self.stats_box)
        self.setLayout(self.layout)

        #============================================

        # Class variables

        self.log_types = {
            "Access" : {"state" :False , "button" : self.access_log_button},
            "Auth" : {"state" :False , "button" : self.auth_log_button},
            "Firewall": {"state" :False , "button" : self.firewall_log_button},
        }

        self.toggle_button(self.access_log_button)


    def generate(self):
        try:
            size = int(self.size_input.text())
        except:
            print("Size must be a positive int to run generation")
        results = generate_logs(
                size,
                100,
                self.log_types["Access"]["state"],
                self.log_types["Auth"]["state"],
                self.log_types["Firewall"]["state"],
        )
        self.update_stats(results)

    def update_stats(self, results):

        stats_message = "Attack Types:"
        stats_message += "\nBruteforce attacks: " + str(results[0])
        stats_message += "\nDirectory Scan attacks: " + str(results[1])
        stats_message += "\nRequest Flood attacks: " + str(results[2])
        stats_message += "\nSQL Injection attacks: " + str(results[3])
        stats_message += "\nExfilation attacks: " + str(results[4])
        stats_message += "\nCommand Injection attacks: " + str(results[5])
        self.true_attack_stats.setText(stats_message)

        profile_counts = results[6]
        log_source_counts = results[7]
        profile_message = "User Distribution and Log Line Soure Distribution:"
        profile_message += "\nNormal users: " + str(profile_counts["normal"]) + " users accounted for " + str(log_source_counts["normal"]) + " log lines"
        profile_message += "\nScanner: " + str(profile_counts["scanner"]) + " users accounted for " + str(log_source_counts["scanner"]) + " log lines"
        profile_message += "\nAttacker: " + str(profile_counts["attacker"]) + " users accounted for " + str(log_source_counts["attacker"]) + " log lines"
        profile_message += "\nComprimised: " + str(profile_counts["compromised"]) + " users accounted for " + str(log_source_counts["compromised"]) + " log lines\n"
        self.actor_stats.setText(profile_message)

    def toggle_button(self, button: QPushButton):
        text = button.text()
        entry = self.log_types[text]

        entry["state"] = not entry["state"]
        if entry["state"]:
            entry["button"].setStyleSheet(f"color: {active_dark_green};")
        else:
            entry["button"].setStyleSheet("")


    