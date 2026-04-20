import sys
from analysis.stats import report_generation_stats, show_actor_distribution
from simulator.log_manager import log_shredder, save_logs


def process_commands(self, command):
    """Parse command tokens, execute actions, and update Whiskers state."""
    self.gen_flag_order = []
    self.size_values = []

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
            save_logs(command[1:])
            break

        elif arg == "shred":
            log_shredder(command[1:])
            break

        # Generation
        elif arg in ("-gac", "--generate_access"):
            self.gen_access = True
            self.gen_new = True
            if "access" not in self.gen_flag_order:
                self.gen_flag_order.append("access")

        elif arg in ("-gauth", "--generate_auth"):
            self.gen_auth = True
            self.gen_new = True
            if "auth" not in self.gen_flag_order:
                self.gen_flag_order.append("auth")
            if not self.auth_logs:
                self.auth_logs = [
                    {"name": "auth", "path": "data/auth.log", "format": "auth"}
                ]

        elif arg in ("-gfire", "--generate_firewall"):
            self.gen_firewall = True
            self.gen_new = True
            if "firewall" not in self.gen_flag_order:
                self.gen_flag_order.append("firewall")
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
            if "access" not in self.gen_flag_order:
                self.gen_flag_order.append("access")
            if "auth" not in self.gen_flag_order:
                self.gen_flag_order.append("auth")
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

        elif arg == "mouse":
            print(self.mouse_art_2[0])

        elif arg in ("-s", "--size"):
            offset, ok = process_size_commands(self, command, i)
            if not ok:
                self.gen_new = False
                break
            i += offset

        else:
            print("Unknown argument:", arg, " use -h or --help for command list")

        i += 1

    if self.gen_new:
        resolved_sizes = resolve_generation_sizes(
            self,
            gen_access=self.gen_access,
            gen_auth=self.gen_auth,
            gen_firewall=self.gen_firewall,
        )
        if resolved_sizes is None:
            self.gen_new = False
            return

        self.access_size = resolved_sizes["access"]
        self.auth_size = resolved_sizes["auth"]
        self.firewall_size = resolved_sizes["firewall"]
        self.size = self.access_size

        print("\n=============== Running Generation ===============\n")
        result = self.run_generation(
            sizes=[resolved_sizes["access"], resolved_sizes["auth"], resolved_sizes["firewall"]],
            users=100,
            gen_access=self.gen_access,
            gen_auth=self.gen_auth,
            gen_firewall=self.gen_firewall,
        )
        print(report_generation_stats(result["attack_counters"]))
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


def process_size_commands(self, command, index):
    """
    Parse one-or-more integer values after -s/--size.
    Returns (offset, ok), where offset is how many tokens were consumed after -s.
    """
    self.size_values = []
    j = index + 1
    while j < len(command):
        token = command[j]
        if token.startswith("-"):
            break
        try:
            parsed = int(token)
        except ValueError:
            print(
                "Invalid -s/--size value. Provide one or more positive integers after -s."
            )
            return 0, False
        if parsed <= 0:
            print("Size values must be positive integers.")
            return 0, False
        self.size_values.append(parsed)
        j += 1

    if not self.size_values:
        print("When using -s/--size, provide at least one integer value.")
        return 0, False

    return len(self.size_values), True


def resolve_generation_sizes(self, *, gen_access: bool, gen_auth: bool, gen_firewall: bool) -> dict[str, int] | None:
    """Resolve per-log generation sizes from parsed CLI options."""
    selected = []
    if gen_access:
        selected.append("access")
    if gen_auth:
        selected.append("auth")
    if gen_firewall:
        selected.append("firewall")

    if not selected:
        return {"access": 2000, "auth": 2000, "firewall": 2000}

    ordered_selected = [name for name in self.gen_flag_order if name in selected]
    for name in selected:
        if name not in ordered_selected:
            ordered_selected.append(name)

    if not self.size_values:
        resolved = {name: 2000 for name in selected}
    elif len(self.size_values) == 1:
        resolved = {name: self.size_values[0] for name in selected}
    else:
        if len(self.size_values) < len(ordered_selected):
            print(
                f"Not enough sizes provided for selected generation flags: expected {len(ordered_selected)}, got {len(self.size_values)}."
            )
            return None
        if len(self.size_values) > len(ordered_selected):
            print(
                f"Too many sizes provided for selected generation flags: expected {len(ordered_selected)}, got {len(self.size_values)}."
            )
            return None
        resolved = {
            log_type: self.size_values[idx]
            for idx, log_type in enumerate(ordered_selected)
        }

    return {
        "access": resolved.get("access", 2000),
        "auth": resolved.get("auth", 2000),
        "firewall": resolved.get("firewall", 2000),
    }
