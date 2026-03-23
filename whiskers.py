import sys
from typing import List, Tuple

import pandas as pd

from analysis.stats import report_detection_stats, show_actor_distribution
from analysis.stats import show_actor_distribution
from parser.log_parser import parse_logs, parse_firewall_logs
from analysis import feature_engineering
from analysis.stats import check_detection_stats
from analysis.detectors import (
    BruteForceDetector,
    ScanDetector,
    FloodDetector,
    SqlInjectionDetector,
    ExfiltrationDetector,
    IsolationForestDetector,
    SupervisedIPClassifierDetector,
)
from simulator.log_simulator import generate_logs
from simulator.log_manager import save_logs, log_shredder

class Whiskers:
    def __init__(self, args):
        self.mode = "normal"
        self.check = False
        self.gen_new = False
        self.run_detection = False
        self.size = 2000
        # default access log sources
        # each entry: {"name": str, "path": str, "format": str}
        self.access_logs = [
            {"name": "access", "path": "data/access.log", "format": "whiskers_access"}
        ]
        # optional firewall log sources
        self.firewall_logs = []
        
        # Initialize detectors with configurable thresholds
        self.detectors = [
            BruteForceDetector(threshold=10),
            ScanDetector(threshold=4),
            FloodDetector(threshold=100),
            SqlInjectionDetector(threshold=2),
            ExfiltrationDetector(threshold=2_000_000),
            IsolationForestDetector(contamination=0.1),
            SupervisedIPClassifierDetector(),
        ]

        # Initialize list for true number of attack types. Will be filled when generating logs
        self.true_attack_counts = {
            "brute_force": 0,
            "directory_scan": 0,
            "request_flood": 0,
            "sql_injection": 0,
            "data_exfiltration": 0
        }

        self.detected_attack_counts = {
            "brute_force": 0,
            "directory_scan": 0,
            "request_flood": 0,
            "sql_injection": 0,
            "data_exfiltration": 0
        }

        # Stats from log generation
        self.profile_counts = {
            "normal": 0,
            "scanner": 0,
            "attacker": 0,
            "compromised": 0
        }

        self.log_source_counts = {
            "normal": 0,
            "scanner": 0,
            "attacker": 0,
            "compromised": 0
        }

        mouse_art_1 = ['''
            ⠀⠀⠀⡎⠑⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⢸⠀⠀⠸⡀⠀⠀⠀⣠⠴⡲⠛⠉⠉⠓⠲⣄⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⣇⡴⢠⠞⢁⠞⠒⠒⠤⠀⠀⠀⠈⢳⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠈⡆⠰⣄⣹⢠⠃⠀⠸⡄⠀⠀⠀⠱⠀⠀⠀⠈⡇⠀⠀⢀⣠⠄
        ⠀⠀⠀⣀⡴⠚⠉⠉⠉⠓⠙⠊⠂⠀⠀⡃⠀⠀⠀⠀⠀⠀⠀⢠⠇⣠⢶⠟⠁⠀
        ⣠⠶⡚⠉⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⡚⠁⠀⠀⡄⠀⠀⠀⢠⠞⡰⢡⠏⠀⠀⠀
        ⢷⠔⠁⠀⠀⠀⠀⡎⠁⣹⡆⠀⠀⠀⠘⡖⠤⢤⡿⣄⠤⠞⠁⠃⡟⠀⠀⠀⠀
        ⠘⣦⠀⢠⠠⡀⠀⠙⠿⠔⠁⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⣼⠀⡇⠀⠀⠀⠀
        ⠀⠈⠳⣄⣧⠙⢆⠀⠀⠀⠀⠀⠀⠀⣠⠞⠀⠀⠀⠀⠀⠀⠀⡿⠀⣇⠀⠀⠀⠀
        ⠀⠀⠀⠈⣻⢦⢈⢧⠀⠀⠀⠀⠐⠉⢡⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⣿⠀⠀⠀⠀
        ⠀⠀⠀⢀⠏⣸⠀⠈⠆⡀⠀⠀⠀⠀⠈⠳⣄⠀⠀⠀⠀⠀⣸⠁⠀⣿⠀⠀⠀⠀
        ⠀⠀⠀⠀⢰⠃⢠⠀⡴⠁⠀⠀⡆⠀⠀⠀⠈⠳⣄⣀⣠⠞⠁⠀⣰⠃⠀⠀⠀⠀
        ⠀⠀⠀⠀⠘⢶⣹⢠⡧⡀⢀⡼⠁⠀⠀⠀⠀⠀⠈⠻⡀⠀⢀⡴⠃⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⢀⡏⠀⠈⠷⠗⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⠴⠋⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠸⣆⠀⢄⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⢀⡞⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⢀⣴⠋⡛⠲⢵⣦⣽⣦⣀⣀⠀⢀⣀⣠⠴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠈⠙⠒⠓⠒⠉⢸⣕⣠⣈⡭⠝⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ''']
        self.mouse_art_2 = ['''
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⡆⠀⢀⡴⠚⠉⠉⠉⠙⠢⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠤⠤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⢻⡇⢰⠋⠀⣠⠴⠲⢤⡀⠀⠘⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⠀⠀⠀⢀⣹⡄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⡼⢣⡞⠀⡏⠀⢰⠁⠀⠀⠀⢱⠀⠀⠹⡄⠀⠀⠀⠀⠀⠀⠀⣠⠏⠀⠀⠀⠀⣠⠟⠁⢹⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⡴⢋⣴⠋⠀⠀⣇⠀⢹⡀⠀⠀⠀⠈⢧⠀⠀⠙⠦⠤⠴⠒⠚⣋⠉⠉⠉⠑⠒⠶⣞⠁⠀⠀⣼⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⡴⢋⣴⠟⠁⠀⠀⠀⠘⣦⡈⠳⣄⡀⠀⠀⠀⠙⠒⣲⠆⠀⠀⢠⡞⠻⣿⣷⡄⠀⠀⠀⠈⠙⢦⡴⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢠⠞⣡⠟⠁⠀⠀⠀⠀⢠⡾⠋⠙⠦⣀⠉⠉⠉⠉⣉⠉⠀⠀⠀⠀⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⢈⣷⠤⣄⡀⠀⠀⠀⠀
⠀⢠⠏⣼⠃⠀⠀⠀⠀⠀⣴⠋⠀⠀⠀⠀⠀⢹⠋⠉⠉⠀⠀⠀⠀⠀⠀⠼⢿⡉⠙⠻⠃⠀⠀⠀⠀⠀⢠⡏⠀⠀⠀⣹⠀⠀⠀⠀
⠀⡞⢰⠇⠀⠀⠀⠀⠀⡼⠁⠀⠀⠀⠀⠀⠀⠸⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⡉⠉⠐⠒⠤⢀⠀⠀⠳⢤⣤⣶⣋⣀⠀⠀⠀
⢰⡇⢸⠀⠀⠀⠀⠀⣸⠃⠀⠀⠀⠀⠀⠀⠀⠀⢳⡀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⣠⡤⠆⣈⡉⠛⠀⠀⢀⡼⢁⡯⢄⡀⠀⠙⠒
⠸⡇⢸⠀⠀⠀⠀⢠⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢉⠷⠾⠥⠤⠤⣴⣾⣿⡤⠚⠳⡀⠉⢢⡀⠀
⠀⣷⠘⣇⠀⠀⠀⢸⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠓⠤⣄⠀⠀⠀⠀⠀⢀⠔⠁⠀⠀⠀⠀⠾⣿⣽⠟⠀⠀⠀⢡⠀⠀⠉⠀
⠀⠘⣧⡹⣆⠀⠀⢿⠀⠀⠀⣶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠓⠒⠢⠤⠤⠤⠤⠤⠤⠤⠴⣾⠋⠀⠀⠀⠀⠀⠘⠀⠀⠀⠀
⠀⠀⠈⠳⣌⡳⠦⣼⡀⠀⢰⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠈⠙⠓⠾⣧⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠙⣧⡀⣷⠀⠀⠀⠀⠀⢀⡶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⣰⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⠛⢻⡆⠀⠀⠀⠀⢸⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡟⠀⠀⢀⣼⣛⣿⡧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠛⠛⠛⠉⢻⣄⠀⠀⠀⢸⠶⠤⣤⣀⣠⣤⡤⠤⠶⢶⠟⠀⠀⣰⠟⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣧⠀⠀⢸⡄⠀⠀⠀⠀⠀⠀⠀⢠⠏⠀⣤⣾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣷⣶⣮⣷⠀⠀⠀⠀⠀⠀⠀⢿⣤⣿⣿⣽⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠙⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ''' ]
        print(mouse_art_1[0])
        print("Generating new Whiskers Agent...")
              
        # Sort out any additional arguments
        self.process_commands(args)



    def show_help(self):
        help_text = """         Startup Usage: python main.py [options]
            Options:
            -h, --help                      Show this help message
            -g, --generate                  Generate new logs
            -s, --size [number]             Base number of actions to generate (default 2000, attacks will generate more log lines)
            -d, --detect                    Rerun detection algorithms on current logs
            -v, --verbose                   Enable verbose output for detect. Shows all detected alerts with details instead of just summary counts.
            -c, --check                     Check for accuracy of detection
            -as, --actor-stats              Show distribution of actor profiles in the generated logs
            -al, --access-log PATH           Use a specific access log file instead of data/access.log
            -ea, --extra-access-log PATH    Add an additional access log file
            -fw, --firewall-log PATH        Add a firewall log file (WIP)

            Additional commands (not used with flags):
            save [filename] [directory]     Save the current access log to a new file with optional directory (default directory is ./data/)
            shred [filename] [directory]    Delete a log file that is no longer needed (default directory is ./data/)
                    
        """

        print(help_text)
    
    def prepare_dataframe(self):
        """Load configured log files into a dataframe and compute features."""
        frames = []
        for src in self.access_logs:
            df_part = parse_logs(src["path"], source=src["name"])
            frames.append(df_part)

        for src in self.firewall_logs:
            df_part = parse_firewall_logs(src["path"], source=src["name"])
            frames.append(df_part)

        if frames:
            self.df = pd.concat(frames, ignore_index=True).sort_values("timestamp")
        else:
            self.df = pd.DataFrame()

        total_files = len(self.access_logs) + len(self.firewall_logs)
        print(f"Parsed {self.df.shape[0]} lines from {total_files} log file(s).")

        # create features for later use
        self.features = feature_engineering.basic_aggregate_features(self.df)
        if self.mode == "verbose":
            print("\n--- feature matrix (by IP) ---")
            print(self.features)
            print("--- end features ---\n")

    def run_detection_models(self):
        """Execute all detectors against the current dataframe and print results."""
        # Reset detected counts so a new run doesn't carry over prior results
        for kind in self.detected_attack_counts:
            self.detected_attack_counts[kind] = 0

        self.all_alerts = []
        for detector in self.detectors:
            alerts = detector.detect(self.df)
            self.all_alerts.extend(alerts)

        report_detection_stats(self.all_alerts, self.detected_attack_counts, self.mode)


    def update_true_attack_counts_from_df(self):
        """Update `self.true_attack_counts` from the parsed log dataframe.

        The log generator tags each attack instance with a `count` value, so each
        unique `count` within an attack classification corresponds to a single
        generated attack instance.
        """
        if not hasattr(self, "df") or self.df is None or self.df.empty:
            for key in self.true_attack_counts:
                self.true_attack_counts[key] = 0
            return

        for key in self.true_attack_counts:
            attack_logs = self.df[self.df["classification"] == key]
            if attack_logs.empty:
                self.true_attack_counts[key] = 0
            else:
                self.true_attack_counts[key] = int(attack_logs["count"].nunique())


    def process_commands(self, command):
        # First pass: parse all arguments
        i = 0
        while i < len(command):
            arg = command[i].lower()

            if arg in ("quit", "exit", "q", "-q", "--quit", "--exit"):
                print("Exiting Whiskers. Stay safe out there!")
                sys.exit(0)

            elif arg == "save":
                # This should only be run as a solo command (with args). Cancel if there are other args to avoid confusion.
                # Expected usage: "save" or "save data/etra_run.log" 
                save_logs(command[1:])  # pass any additional args to save_logs for filename/directory handling
                break # break to avoid processing any additional args after save command

            elif arg == "shred":
                # This should only be run as a solo command (with args). Cancel if there are other args to avoid confusion.
                log_shredder(command[1:])  # pass any additional args to log_shredder for filename/directory handling
                break # break to avoid processing any additional args after shred command

            elif arg in ("-h", "--help"):
                self.show_help()

            elif arg in ("-v", "--verbose"):
                self.mode = "verbose"
            
            elif arg in ("-g", "--generate"):
                self.gen_new = True

            elif arg in ("-d", "--detect"):
                self.run_detection = True

            elif arg in ("-c", "--check"):
                self.check = True
            
            elif arg in ("-s", "--size"):
                try:
                    self.size = int(command[i + 1])
                    print(f"Set log size to {self.size}")
                    i += 1  # skip the value we just consumed
                except (ValueError, IndexError):
                    print("Invalid size argument. Using default value of 2000.")

            elif arg in ("-al", "--access-log", "access-log"):
                try:
                    path = command[i + 1]
                    self.access_logs = [
                        {"name": "access", "path": path, "format": "whiskers_access"}
                    ]
                    i += 1
                except IndexError:
                    print("Invalid or missing path for --access-log; keeping default data/access.log.")

            elif arg in ("-ea", "--extra-access-log"):
                try:
                    path = command[i + 1]
                    self.access_logs.append(
                        {"name": "access", "path": path, "format": "whiskers_access"}
                    )
                    i += 1
                except IndexError:
                    print("Invalid or missing path for --extra-access-log; ignoring.")

            elif arg in ("-fw", "--firewall-log"):
                try:
                    path = command[i + 1]
                    self.firewall_logs.append(
                        {"name": "firewall", "path": path, "format": "whiskers_firewall"}
                    )
                    i += 1
                except IndexError:
                    print("Invalid or missing path for --firewall-log; ignoring.")
            
            elif arg in ("-as", "--actor-stats"):
                show_actor_distribution(self.profile_counts, self.log_source_counts)
                break

            elif arg == "mouse":
                print(self.mouse_art_2[0])

            else:
                print("Unknown argument:", arg, " use -h or --help for command list")

            i += 1

        # Second pass: execute actions after all arguments are parsed
        if self.gen_new:
            results = generate_logs(size=self.size)
            self.profile_counts = results[5]
            self.log_source_counts = results[6]
            self.gen_new = False
            self.mode = "normal"
        
        if self.run_detection:
            self.prepare_dataframe()
            self.update_true_attack_counts_from_df()
            self.run_detection_models()
            self.run_detection = False

        if self.check:
            check_detection_stats(self.true_attack_counts, self.detected_attack_counts)
            self.check = False

    def await_input(self):
        while True:
            user_input = input("Awaiting task for Whiskers...\n").lower()
            command = user_input.strip().split()
            self.process_commands(command)

            