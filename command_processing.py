import sys
from collections.abc import Callable

from analysis.stats import report_generation_stats, show_actor_distribution
from simulator.log_manager import save_logs, shred_logs

_ACCESS_SRC = {"name": "access", "path": "data/access.log", "format": "access"}
_AUTH_SRC = {"name": "auth", "path": "data/auth.log", "format": "auth"}
_FIREWALL_SRC = {"name": "firewall", "path": "data/firewall.log", "format": "firewall"}
_COMMAND_HANDLERS: dict[str, Callable] = {}


def command_handler(*aliases: str) -> Callable:
    """Register a parse_commands handler for one or more command aliases."""

    def decorator(func: Callable) -> Callable:
        for alias in aliases:
            _COMMAND_HANDLERS[alias.lower()] = func
        return func

    return decorator


@command_handler("-h", "--help")
def handle_help(self, _command: list[str], _index: int) -> bool:
    self.show_help()
    return False


@command_handler("-ui", "--ui")
def handle_ui(self, _command: list[str], _index: int) -> bool:
    self.open_ui()
    return False


@command_handler("quit", "exit", "q", "-q", "--quit", "--exit")
def handle_quit(_self, _command: list[str], _index: int) -> bool:
    print("Exiting Whiskers. Stay safe out there!")
    sys.exit(0)


@command_handler("save")
def handle_save(self, command: list[str], _index: int) -> bool:
    """Run the save command and stop further parsing."""
    save_logs(self, command[1:])
    return True


@command_handler("shred")
def handle_shred(self, command: list[str], _index: int) -> bool:
    """Run the shred command and stop further parsing."""
    shred_logs(self, command[1:])
    return True


@command_handler("-gac", "--generate_access")
def handle_generate_access(self, _command: list[str], _index: int) -> bool:
    self.gen_access = True
    self.gen_new = True
    record_gen_flag(self, "access")
    return False


@command_handler("-gauth", "--generate_auth")
def handle_generate_auth(self, _command: list[str], _index: int) -> bool:
    self.gen_auth = True
    self.gen_new = True
    record_gen_flag(self, "auth")
    return False


@command_handler("-gfire", "--generate_firewall")
def handle_generate_firewall(self, _command: list[str], _index: int) -> bool:
    self.gen_firewall = True
    self.gen_new = True
    record_gen_flag(self, "firewall")
    return False


@command_handler("-g", "--generate")
def handle_generate(self, _command: list[str], _index: int) -> bool:
    self.gen_access = True
    self.gen_auth = True
    self.gen_new = True
    record_gen_flag(self, "access")
    record_gen_flag(self, "auth")
    return False


@command_handler("-d", "--detect")
def handle_detect(self, _command: list[str], _index: int) -> bool:
    self.run_detection = True
    set_detect_sources(self, access=True, auth=True, firewall=False)
    return False


@command_handler("-dac", "--detect_access")
def handle_detect_access(self, _command: list[str], _index: int) -> bool:
    self.run_detection = True
    set_detect_sources(self, access=True, auth=False, firewall=False)
    return False


@command_handler("-dauth", "--detect_auth")
def handle_detect_auth(self, _command: list[str], _index: int) -> bool:
    self.run_detection = True
    set_detect_sources(self, access=False, auth=True, firewall=False)
    return False


@command_handler("-v", "--verbose")
def handle_verbose(self, _command: list[str], _index: int) -> bool:
    self.mode = "verbose"
    return False


@command_handler("-c", "--check")
def handle_check(self, _command: list[str], _index: int) -> bool:
    self.check = True
    return False


@command_handler("-as", "--actor-stats")
def handle_actor_stats(self, _command: list[str], _index: int) -> bool:
    show_actor_distribution(self.profile_counts, self.log_source_counts)
    return True


@command_handler("mouse")
def handle_mouse(self, _command: list[str], _index: int) -> bool:
    print(self.mouse_art_2[0])
    return False


def reset_parse_state(self) -> None:
    self.gen_flag_order = []
    self.size_values = []


def set_detect_sources(self, *, access: bool, auth: bool, firewall: bool) -> None:
    self.access_logs = [_ACCESS_SRC.copy()] if access else []
    self.auth_logs = [_AUTH_SRC.copy()] if auth else []
    self.firewall_logs = [_FIREWALL_SRC.copy()] if firewall else []


def ensure_generate_sources(self) -> None:
    if self.gen_auth and not self.auth_logs:
        self.auth_logs = [_AUTH_SRC.copy()]
    if self.gen_firewall and not self.firewall_logs:
        self.firewall_logs = [_FIREWALL_SRC.copy()]


def record_gen_flag(self, name: str) -> None:
    if name not in self.gen_flag_order:
        self.gen_flag_order.append(name)


def parse_commands(self, command: list[str]) -> None:
    i = 0
    while i < len(command):
        arg = command[i].lower()
        handler = _COMMAND_HANDLERS.get(arg)
        if handler is not None:
            should_stop = handler(self, command, i)
            if should_stop:
                return
            i += 1
            continue

        if arg in ("-al", "--access-log", "access-log"):
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
                self.auth_logs.append({"name": "auth", "path": path, "format": "auth"})
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
        elif arg in ("-s", "--size"):
            offset, ok = process_size_commands(self, command, i)
            if not ok:
                self.gen_new = False
                return
            i += offset
        else:
            print("Unknown argument:", arg, " use -h or --help for command list")

        i += 1


def run_generation_if_requested(self) -> None:
    if not self.gen_new:
        return
    ensure_generate_sources(self)
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
        sizes=[
            resolved_sizes["access"],
            resolved_sizes["auth"],
            resolved_sizes["firewall"],
        ],
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


def run_detection_if_requested(self) -> None:
    if not self.run_detection:
        return
    print("\n=============== Running Detection ===============\n")
    print(self.run_detection_pipeline())
    self.run_detection = False
    set_detect_sources(self, access=True, auth=False, firewall=False)


def run_check_if_requested(self) -> None:
    if not self.check:
        return
    print("\n=============== Running Checking ===============\n")
    print(self.run_check_report())
    self.check = False


def process_commands(self, command):
    """Parse command tokens, execute actions, and update Whiskers state."""
    reset_parse_state(self)
    parse_commands(self, command)
    run_generation_if_requested(self)
    run_detection_if_requested(self)
    run_check_if_requested(self)


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


def resolve_generation_sizes(
    self, *, gen_access: bool, gen_auth: bool, gen_firewall: bool
) -> dict[str, int] | None:
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
