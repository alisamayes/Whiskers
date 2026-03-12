import sys
from typing import List, Tuple

import pandas as pd

from parser.log_parser import parse_logs, parse_firewall_logs
from analysis import feature_engineering
from analysis.check_detection import check_detection
from analysis.detectors import (
    BruteForceDetector,
    ScanDetector,
    FloodDetector,
    SqlInjectionDetector,
    ExfiltrationDetector,
)
from simulator.log_simulator import generate_logs

class Whiskers:
    def __init__(self, args):
        self.mode = "normal"
        self.check = False
        self.gen_new = False
        self.run_detection = False
        self.size = 2000
        # default access log sources
        self.access_logs: List[Tuple[str, str]] = [("access", "data/access.log")]
        # optional firewall log sources
        self.firewall_logs: List[Tuple[str, str]] = []
        
        # Initialize detectors with configurable thresholds
        self.detectors = [
            BruteForceDetector(threshold=10),
            ScanDetector(threshold=4),
            FloodDetector(threshold=100),
            SqlInjectionDetector(threshold=2),
            ExfiltrationDetector(threshold=2_000_000),
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

        mouse_art_1 = ['''
    ⠀⠀⠀⡎⠑⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢸⠀⠀⠸⡀⠀⠀⠀⣠⠴⡲⠛⠉⠉⠓⠲⣄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⣇⡴⢠⠞⢁⠞⠒⠒⠤⠀⠀⠀⠈⢳⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⡆⠰⣄⣹⢠⠃⠀⠸⡄⠀⠀⠀⠱⠀⠀⠀⠈⡇⠀⠀⢀⣠⠄
⠀⠀⠀⣀⡴⠚⠉⠉⠉⠓⠙⠊⠂⠀⠀⡃⠀⠀⠀⠀⠀⠀⠀⢠⠇⣠⢶⠟⠁⠀
⣠⠶⡚⠉⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⡚⠁⠀⠀⡄⠀⠀⠀⢠⠞⡰⢡⠏⠀⠀⠀
⢷⠔⠁⠀⠀⠀⠀⡎⠁⣹⡆⠀⠀⠀⠘⡖⠤⢤⡿⣄⠤⠞⠁⢰⠃⡟⠀⠀⠀⠀
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

        # load and combine all configured logs and prepare features
        #self.prepare_dataframe()

        # run the configured detectors and display results
        #self.run_detection_models()



    def show_help(self):
        help_text = """         Startup Usage: python main.py [options]
            Options:
            -v, --verbose                   Enable verbose output
            -h, --help                      Show this help message
            -g, --generate                  Generate new logs
            -d, --detect                    Rerun detection algorithms on current logs
            -s, --show                      Show current feature matrix and detections
            -c, --check                     Check for accuracy of detection
            -s, --size [number]             Base number of log lines to generate (default 2000, attacks will generate more lines)
            -a, --access-log PATH           Use a specific access log file instead of data/access.log
            -ea, --extra-access-log PATH    Add an additional access log file
            -fw, --firewall-log PATH        Add a firewall log file
                    
        """

        print(help_text)
    
    def prepare_dataframe(self):
        """Load configured log files into a dataframe and compute features."""
        frames = []
        for source_name, path in self.access_logs:
            df_part = parse_logs(path, source=source_name)
            frames.append(df_part)

        for source_name, path in self.firewall_logs:
            df_part = parse_firewall_logs(path, source=source_name)
            frames.append(df_part)

        if frames:
            self.df = pd.concat(frames, ignore_index=True).sort_values("timestamp")
        else:
            self.df = pd.DataFrame()

        total_files = len(self.access_logs) + len(self.firewall_logs)
        print(f"Parsed {len(self.df)} log entries from {total_files} log file(s).")

        # create features for later use
        self.features = feature_engineering.basic_aggregate_features(self.df)
        if self.mode == "verbose":
            print("\n--- feature matrix (by IP) ---")
            print(self.features)
            print("--- end features ---\n")

    def run_detection_models(self):
        """Execute all detectors against the current dataframe and print results."""
        self.all_alerts = []
        for detector in self.detectors:
            alerts = detector.detect(self.df)
            self.all_alerts.extend(alerts)

        if self.mode == "verbose":
            print("\n--- threat detections ---")
            by_kind = {}
            for alert in self.all_alerts:
                by_kind.setdefault(alert.kind, []).append(alert)

            for kind, alerts_of_kind in by_kind.items():
                print(f"\n{kind.upper()} ({len(alerts_of_kind)} total):")
                self.detected_attack_counts[kind] = len(alerts_of_kind)
                for alert in alerts_of_kind:
                    print(f"  ⚠ {alert}")
            print("--- end detections ---\n")
        else:
            # Summary view
            by_kind = {}
            for alert in self.all_alerts:
                by_kind[alert.kind] = by_kind.get(alert.kind, 0) + 1
            for kind, count in by_kind.items():
                print(f"{kind.replace('_', ' ').title()} attempts detected: {count}")
                self.detected_attack_counts[kind] = count

        


    def process_commands(self, command):
        # First pass: parse all arguments
        i = 0
        while i < len(command):
            arg = command[i]
            
            if arg in ("exit", "quit", "q"):
                print("Exiting Whiskers. Stay safe out there!")
                sys.exit(0)

            if arg in ("-h", "--help", "help"):
                self.show_help()

            elif arg in ("-v", "--verbose", "verbose"):
                self.mode = "verbose"
            
            elif arg in ("-g", "--generate", "generate"):
                self.gen_new = True

            elif arg in ("-d", "--detect", "detect"):
                self.run_detection = True

            elif arg in ("-c", "--check", "check"):
                self.check = True
            
            elif arg in ("-s", "--size", "size"):
                try:
                    self.size = int(command[i + 1])
                    print(f"Set log size to {self.size}")
                    i += 1  # skip the value we just consumed
                except (ValueError, IndexError):
                    print("Invalid size argument. Using default value of 2000.")

            elif arg in ("-a", "--access-log", "access-log"):
                try:
                    path = command[i + 1]
                    self.access_logs = [("access", path)]
                    i += 1
                except IndexError:
                    print("Invalid or missing path for --access-log; keeping default data/access.log.")

            elif arg in ("-ea", "--extra-access-log", "extra-access-log"):
                try:
                    path = command[i + 1]
                    self.access_logs.append(("access", path))
                    i += 1
                except IndexError:
                    print("Invalid or missing path for --extra-access-log; ignoring.")

            elif arg in ("-fw", "--firewall-log", "firewall-log"):
                try:
                    path = command[i + 1]
                    self.firewall_logs.append(("firewall", path))
                    i += 1
                except IndexError:
                    print("Invalid or missing path for --firewall-log; ignoring.")

            elif arg == "mouse":
                print(self.mouse_art_2[0])

            else:
                print("Unknown argument:", arg, " use -h or --help for command list")

            i += 1

        # Second pass: execute actions after all arguments are parsed
        if self.gen_new:
            true_counts = generate_logs(size=self.size)
            for attack in self.true_attack_counts:
                self.true_attack_counts[attack] = true_counts[list(self.true_attack_counts.keys()).index(attack)]
            self.gen_new = False
            self.mode = "normal"
        
        if self.run_detection:
            self.prepare_dataframe()
            self.run_detection_models()
            self.run_detection = False

        if self.check:
            check_detection(self.true_attack_counts, self.detected_attack_counts)
            self.check = False

    def await_input(self):
        while True:
            user_input = input("Awaiting task for Whiskers...\n").lower()
            command = user_input.strip().split()
            self.process_commands(command)

            