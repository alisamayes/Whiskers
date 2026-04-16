import sys
import threading
from parser.log_parser import parse_auth_logs, parse_firewall_logs, parse_logs
from typing import List, Optional, Tuple

import pandas as pd

from analysis import feature_engineering
from analysis.detectors import (
    AuthPrivilegeEscalationChain,
    AuthSshBruteforceDetector,
    AuthSshUserEnumDetector,
    AuthSudoBruteforceDetector,
    BruteForceDetector,
    CommandInjectionDetector,
    ExfiltrationDetector,
    FloodDetector,
    IsolationForestDetector,
    ScanDetector,
    SqlInjectionDetector,
    SupervisedIPClassifierDetector,
)
from analysis.stats import (
    report_check_stats,
    report_detection_stats,
    show_actor_distribution,
)
from simulator.log_manager import log_shredder, save_logs
from simulator.log_simulator import generate_logs


def normalize_timestamps_utc(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize ``timestamp`` to timezone-aware UTC for all log sources."""
    if df.empty or "timestamp" not in df.columns:
        return df
    out = df.copy()
    ts = pd.to_datetime(out["timestamp"], utc=True)
    out["timestamp"] = ts
    return out


class Whiskers:
    def __init__(self, args):
        """Initialize runtime state, detectors, and process startup arguments."""
        # Avoid Windows console UnicodeEncodeError when printing banner art.
        # (PowerShell/terminal encoding can be cp1252; we prefer UTF-8 with replacement.)
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

        self.mode = "normal"
        self.check = False
        self.gen_new = False
        self.gen_access = False
        self.gen_auth = False
        self.gen_firewall = False
        self.run_detection = False
        self.size = 2000
        # default access log sources
        # each entry: {"name": str, "path": str, "format": str}
        self.access_logs = [
            {"name": "access", "path": "data/access.log", "format": "access"}
        ]
        # optional firewall log sources
        self.firewall_logs = []
        # optional Linux auth log sources (auth.log / secure)
        self.auth_logs = []

        # Initialize detectors with configurable thresholds
        self.detectors = [
            BruteForceDetector(threshold=10),
            ScanDetector(threshold=4),
            FloodDetector(threshold=100),
            SqlInjectionDetector(threshold=2),
            ExfiltrationDetector(threshold=2_000_000),
            CommandInjectionDetector(threshold=2),
            AuthSshBruteforceDetector(threshold=8, session_gap_seconds=90),
            AuthSshUserEnumDetector(threshold=12, session_gap_seconds=90),
            AuthSudoBruteforceDetector(threshold=5, session_gap_seconds=180),
            AuthPrivilegeEscalationChain(
                threshold=3,
                window_seconds=600,
                first_fail_max_seconds=240,
                heuristic_threshold=5,
            ),
            IsolationForestDetector(),
            SupervisedIPClassifierDetector(),
        ]

        # Initialize list for true number of attack types. Will be filled when generating logs
        self.true_attack_counts = {
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

        self.detected_attack_counts = {
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

        # Stats from log generation
        self.profile_counts = {
            "normal": 0,
            "scanner": 0,
            "attacker": 0,
            "compromised": 0,
        }

        self.log_source_counts = {
            "normal": 0,
            "scanner": 0,
            "attacker": 0,
            "compromised": 0,
        }
        self.ips_that_attacked = {}
        self.auth_line_count = 0

        mouse_art_1 = ["""
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
        """]
        self.mouse_art_2 = ["""
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
        """]
        print(mouse_art_1[0])
        print("Generating new Whiskers Agent...")

        self.gui_lock = threading.Lock()
        self.gui_ready = threading.Event()
        self.gui_thread: Optional[threading.Thread] = None
        self.app = None
        self.gui_window = None
        self.ui_bridge = None

        # Sort out any additional arguments
        self.process_commands(args)

    def show_help(self):
        """Print CLI usage, flags, and auxiliary file-management commands."""
        help_text = """         Startup Usage: python main.py [options]
            OPTIONS:

            General:
            -h, --help                      Show this help message
            -ui, --ui                       Open the graphical user interface
            q , quit, exit                  Close Whiskers

            Generation:
            -gac, --generate_access         Generate new access log (data/access.log)
            -gauth, --generate_auth         Generate new auth log (data/auth.log)
            -gfire, --generate_firewall     Generate new firewall log (data/firewall.log)
            -s, --size [number]             Base number of actions to generate (default 2000, attacks will generate more log lines)

            Detection:
            -d, --detect                    Run detection algorithms on all current logs
            -dac, --detect-access           Run detection algorithms on access.log (unless other path specified)
            -dauth, --detect-auth           Run detection algorithms on auth.log (unless other path specified)
            -v, --verbose                   Enable verbose output for detect. Shows all detected alerts with details instead of just summary counts.
            -al, --access-log [PATH]        Use a specific access log file instead of data/access.log
            -au, --auth-log [PATH]          Use a specific Linux auth log file instead of data/auth.log
            -fw, --firewall-log [PATH]      Use a specific firewall log file instead of data/firewall.log (WIP)
            
            Checking:
            -c, --check                     Check for accuracy of detection
            -as, --actor-stats              Show distribution of actor profiles in the generated logs

            Log managment:
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

        for src in self.auth_logs:
            df_part = parse_auth_logs(src["path"], source=src["name"])
            frames.append(df_part)

        if frames:
            self.df = pd.concat(frames, ignore_index=True)
            self.df = normalize_timestamps_utc(self.df)
            self.df = self.df.sort_values("timestamp")
        else:
            self.df = pd.DataFrame()

        total_files = (
            len(self.access_logs) + len(self.firewall_logs) + len(self.auth_logs)
        )
        self.features = feature_engineering.basic_aggregate_features(self.df)

    def run_detection_models(self):
        """Execute all detectors against the current dataframe and print results."""
        # Reset detected counts so a new run doesn't carry over prior results
        for kind in self.detected_attack_counts:
            self.detected_attack_counts[kind] = 0

        self.all_alerts = []
        ml_summary = None
        for detector in self.detectors:
            alerts = detector.detect(self.df)
            self.all_alerts.extend(alerts)
            if getattr(detector, "kind", None) == "ml_anomaly":
                ml_summary = getattr(detector, "last_run_summary", None)

        return report_detection_stats(
            self.all_alerts,
            self.detected_attack_counts,
            self.mode,
            ml_summary=ml_summary,
        )

    def run_generation(
        self,
        *,
        size: int | None = None,
        users: int = 100,
        gen_access: bool | None = None,
        gen_auth: bool | None = None,
        gen_firewall: bool | None = None,
    ) -> dict:
        """Run simulator generation and synchronize engine state from one result object."""
        result = generate_logs(
            self.size if size is None else size,
            users,
            self.gen_access if gen_access is None else gen_access,
            self.gen_auth if gen_auth is None else gen_auth,
            self.gen_firewall if gen_firewall is None else gen_firewall,
        )
        self.true_attack_counts = result["attack_counters"].copy()
        self.profile_counts = result["profile_counts"]
        self.log_source_counts = result["log_source_counts"]
        self.ips_that_attacked = result["ips_that_attacked"]
        self.auth_line_count = int(result["auth_line_count"])
        return result

    def run_detection_pipeline(self) -> str:
        """Prepare data, refresh true counts, and execute all detectors."""
        self.prepare_dataframe()
        self.update_true_attack_counts_from_df()
        return self.run_detection_models()

    def run_check_report(self) -> str:
        """Build and return the check report from current engine state."""
        return report_check_stats(
            self.true_attack_counts,
            self.detected_attack_counts,
            self.ips_that_attacked,
            self.profile_counts,
            self.log_source_counts,
        )

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
        """Parse command tokens, execute actions, and update Whiskers state."""
        # First pass: parse all arguments
        i = 0
        while i < len(command):
            arg = command[i].lower()

            # General (matches help text order)
            if arg in ("-h", "--help"):
                self.show_help()

            elif arg in ("-ui", "--ui"):
                self.open_ui()

            elif arg in ("quit", "exit", "q", "-q", "--quit", "--exit"):
                print("Exiting Whiskers. Stay safe out there!")
                sys.exit(0)

            # Log management
            elif arg == "save":
                # This should only be run as a solo command (with args). Cancel if there are other args to avoid confusion.
                # Expected usage: "save" or "save data/etra_run.log"
                save_logs(
                    command[1:]
                )  # pass any additional args to save_logs for filename/directory handling
                break  # break to avoid processing any additional args after save command

            elif arg == "shred":
                # This should only be run as a solo command (with args). Cancel if there are other args to avoid confusion.
                log_shredder(
                    command[1:]
                )  # pass any additional args to log_shredder for filename/directory handling
                break  # break to avoid processing any additional args after shred command

            # Generation
            elif arg in ("-gac", "--generate_access"):
                self.gen_access = True
                self.gen_new = True

            elif arg in ("-gauth", "--generate_auth"):
                self.gen_auth = True
                self.gen_new = True
                if not self.auth_logs:
                    self.auth_logs = [
                        {"name": "auth", "path": "data/auth.log", "format": "auth"}
                    ]

            elif arg in ("-gfire", "--generate_firewall"):
                self.gen_firewall = True
                self.gen_new = True
                if not self.firewall_logs:
                    self.firewall_logs = [
                        {
                            "name": "firewall",
                            "path": "data/firewall.log",
                            "format": "firewall",
                        }
                    ]

            elif arg in ("-g", "--generate"):
                self.gen_access = True
                self.gen_auth = True
                self.gen_new = True
                if not self.auth_logs:
                    self.auth_logs = [
                        {"name": "auth", "path": "data/auth.log", "format": "auth"}
                    ]

            # Detection
            elif arg in ("-d", "--detect"):
                self.run_detection = True
                self.access_logs = [
                    {"name": "access", "path": "data/access.log", "format": "access"}
                ]
                self.auth_logs = [
                    {"name": "auth", "path": "data/auth.log", "format": "auth"}
                ]

            elif arg in ("-dac", "--detect_access"):
                self.run_detection = True
                self.access_logs = [
                    {"name": "access", "path": "data/access.log", "format": "access"}
                ]
                self.auth_logs = []
                self.firewall_logs = []

            elif arg in ("-dauth", "--detect_auth"):
                # Detect using auth logs only
                self.run_detection = True
                self.auth_logs = [
                    {"name": "auth", "path": "data/auth.log", "format": "auth"}
                ]
                self.access_logs = []
                self.firewall_logs = []

            elif arg in ("-v", "--verbose"):
                self.mode = "verbose"

            elif arg in ("-al", "--access-log", "access-log"):
                try:
                    path = command[i + 1]
                    self.access_logs = [
                        {"name": "access", "path": path, "format": "access"}
                    ]
                    i += 1
                except IndexError:
                    print(
                        "Invalid or missing path for --access-log; keeping default data/access.log."
                    )

            elif arg in ("-au", "--auth-log"):
                try:
                    path = command[i + 1]
                    self.auth_logs.append(
                        {"name": "auth", "path": path, "format": "auth"}
                    )
                    i += 1
                except IndexError:
                    print("Invalid or missing path for --auth-log; ignoring.")

            elif arg in ("-fw", "--firewall-log"):
                try:
                    path = command[i + 1]
                    self.firewall_logs.append(
                        {"name": "firewall", "path": path, "format": "firewall"}
                    )
                    i += 1
                except IndexError:
                    print("Invalid or missing path for --firewall-log; ignoring.")

            # Checking
            elif arg in ("-c", "--check"):
                self.check = True

            elif arg in ("-as", "--actor-stats"):
                show_actor_distribution(self.profile_counts, self.log_source_counts)
                break

            # Hidden / fun commands (not in help)
            elif arg == "mouse":
                print(self.mouse_art_2[0])

            # Misc options
            elif arg in ("-s", "--size"):
                try:
                    self.size = int(command[i + 1])
                    print(f"Set log size to {self.size}")
                    i += 1  # skip the value we just consumed
                except (ValueError, IndexError):
                    print("Invalid size argument. Using default value of 2000.")

            else:
                print("Unknown argument:", arg, " use -h or --help for command list")

            i += 1

        # Second pass: execute actions after all arguments are parsed
        if self.gen_new:
            print("\n=============== Running Generation ===============\n")
            self.run_generation(
                size=self.size,
                users=100,
                gen_access=self.gen_access,
                gen_auth=self.gen_auth,
                gen_firewall=self.gen_firewall,
            )
            print(report_generation_stats(attack_counters))
            self.gen_new = False
            self.gen_access = False
            self.gen_auth = False
            self.gen_firewall = False
            self.mode = "normal"

        if self.run_detection:
            print("\n=============== Running Detection ===============\n")
            print(self.run_detection_pipeline())
            self.run_detection = False
            self.access_logs = [
                {"name": "access", "path": "data/access.log", "format": "access"}
            ]
            self.auth_logs = []
            self.firewall_logs = []

        if self.check:
            print("\n=============== Running Checking ===============\n")
            print(self.run_check_report())
            self.check = False

    def open_ui(self) -> None:
        """Open the Qt UI, creating the GUI thread if needed."""
        with self.gui_lock:
            need_start = self.gui_thread is None or not self.gui_thread.is_alive()
            if need_start:
                self.gui_ready.clear()
                self.gui_thread = threading.Thread(
                    target=self.run_gui_thread,
                    daemon=True,
                    name="WhiskersQt",
                )
                self.gui_thread.start()
                if not self.gui_ready.wait(timeout=30.0):
                    print("Whiskers UI failed to start (timed out).")
                    return
                return
            bridge = self.ui_bridge

        if bridge is not None:
            bridge.show_ui.emit()
        else:
            print("Whiskers UI is not available.")

    def run_gui_thread(self) -> None:
        """Run the Qt event loop in a dedicated thread."""
        from PyQt6.QtWidgets import QApplication

        from GUI.main_window import ApplicationWindow, UiBridge, load_window_icon

        # Windows taskbar uses python.exe unless the process has its own AppUserModelID.
        if sys.platform == "win32":
            try:
                import ctypes

                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                    "Whiskers.Whiskers.Desktop.1"
                )
            except Exception:
                pass

        try:
            self.app = QApplication([sys.argv[0]])
        except Exception as e:
            print(f"Whiskers UI: could not start ({e})")
            self.gui_ready.set()
            return

        self.app.setQuitOnLastWindowClosed(False)
        self.app.setWindowIcon(load_window_icon())
        self.gui_window = ApplicationWindow(self)
        window = self.gui_window
        window.close_hides_only = True
        window.whiskers = self

        self.ui_bridge = UiBridge()

        def bring_to_front() -> None:
            """Show the existing window and request focus."""
            window.show()
            window.raise_()
            window.activateWindow()

        self.ui_bridge.show_ui.connect(bring_to_front)

        window.show()
        self.gui_ready.set()
        self.app.exec()

    def await_input(self):
        """Run an interactive command loop for terminal usage."""
        while True:
            user_input = input("Awaiting task for Whiskers...\n").lower()
            command = user_input.strip().split()
            self.process_commands(command)
