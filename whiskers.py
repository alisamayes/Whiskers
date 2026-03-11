import sys
from typing import List, Tuple

import pandas as pd

from parser.log_parser import parse_logs, parse_firewall_logs
from analysis import feature_engineering
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

        mouse_art = ['''
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
        print(mouse_art[0])
        print("Generating new Whiskers Agent...")
              
        # Sort out any additional arguments
        if len(args) > 0:
            for arg in args:
                if arg in ("-h", "--help"):
                    print("Usage: python main.py [options]")
                    print("Options:")
                    print("  -v, --verbose          Enable verbose output")
                    print("  -h, --help             Show this help message")
                    print("  -g, --generate         Generate new logs")
                    print("  -c, --check            Check for accuracy of detection")
                    print("  -s, --size [number]    Base number of log lines to generate (default 2000, attacks will generate more lines)")
                    print("  -a, --access-log PATH  Use a specific access log file instead of data/access.log")
                    print("      --extra-access-log PATH   Add an additional access log file")
                    print("      --firewall-log PATH       Add a firewall log file")
                    sys.exit(0)

                elif arg in ("-v", "--verbose"):
                    self.mode = "verbose"
                
                elif arg in ("-g", "--generate"):
                    print("Generating logs...")
                    self.gen_new = True

                elif arg in ("-c", "--check"):
                    self.check = True
                
                elif arg in ("-s", "--size"):
                    try:
                        # verify new logs are being generated this run
                        if "-g" not in args and "--generate" not in args:
                            print("Size argument ignored since new logs are not being generated. Use -g or --generate to enable log generation along with the size option.")
                        else:
                            size = int(args[args.index(arg) + 1])
                            self.size = size
                            #skip next arg since it's the size value
                        args.pop(args.index(arg) + 1)
                    except (ValueError, IndexError):
                        print("Invalid size argument. Using default value of 2000.")

                elif arg in ("-a", "--access-log"):
                    try:
                        path = args[args.index(arg) + 1]
                        # replace default with single explicit access log
                        self.access_logs = [("access", path)]
                        args.pop(args.index(arg) + 1)
                    except (ValueError, IndexError):
                        print("Invalid or missing path for --access-log; keeping default data/access.log.")

                elif arg == "--extra-access-log":
                    try:
                        path = args[args.index(arg) + 1]
                        self.access_logs.append(("access", path))
                        args.pop(args.index(arg) + 1)
                    except (ValueError, IndexError):
                        print("Invalid or missing path for --extra-access-log; ignoring.")

                elif arg == "--firewall-log":
                    try:
                        path = args[args.index(arg) + 1]
                        self.firewall_logs.append(("firewall", path))
                        args.pop(args.index(arg) + 1)
                    except (ValueError, IndexError):
                        print("Invalid or missing path for --firewall-log; ignoring.")

                else:
                    print("Unknown argument:", arg, " use -v or --verbose for verbose mode")


        if self.gen_new:
            (
                self.bfs,
                self.scs,
                self.fls,
                self.sqli,
                self.exf,
            ) = generate_logs(size=self.size)
            print(
                "Generated logs with "
                f"{self.bfs} brute force attacks, "
                f"{self.scs} directory scans, "
                f"{self.fls} request floods, "
                f"{self.sqli} SQL injection attacks, and "
                f"{self.exf} data exfiltration attempts."
            )

        # load and combine all configured logs
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

        # create a simple feature matrix that future machine learning models
        # can consume.  we keep it around on the instance for later use.
        self.features = feature_engineering.basic_aggregate_features(self.df)
        if self.mode == "verbose":
            print("\n--- feature matrix (by IP) ---")
            print(self.features)
            print("--- end features ---\n")

        # Run all detectors and aggregate alerts
        self.all_alerts = []
        for detector in self.detectors:
            alerts = detector.detect(self.df)
            self.all_alerts.extend(alerts)

        # Display results grouped by detector type
        if self.mode == "verbose":
            print("\n--- threat detections ---")
            by_kind = {}
            for alert in self.all_alerts:
                if alert.kind not in by_kind:
                    by_kind[alert.kind] = []
                by_kind[alert.kind].append(alert)
            
            for kind, alerts_of_kind in by_kind.items():
                print(f"\n{kind.upper()} ({len(alerts_of_kind)} total):")
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