# Whiskers

Whiskers is a learning-focused cybersecurity log analysis toolkit. It combines rule-based threat detection and machine-learning signals over generated or real log files.

This project is for learning and demonstration, not production real-time defense.

## Goals

- Improve Python engineering and project organization
- Explore practical cyber threat detection techniques
- Combine deterministic detectors with ML anomaly/classification signals
- Expand parser and detector coverage incrementally

## What Whiskers does

- Parse multiple log formats into a normalized dataframe
- Generate synthetic logs for repeatable testing and learning
- Detect suspicious behavior with rule-based detectors
- Run ML scoring (anomaly + supervised IP classification)
- Produce detection/check reports and actor profile stats
- Provide both CLI and GUI workflows

## Supported log sources

- Apache-style access logs
- Linux auth logs (`auth.log` / `secure` style)
- Firewall logs (experimental support)

## Detection coverage

### Access log detectors

- Brute force
- Directory traversal / scanning
- Request flood / DDoS-style bursts
- SQL injection patterns
- Command injection patterns
- Data exfiltration indicators

### Auth log detectors

- SSH brute force
- SSH user enumeration
- Sudo brute force
- Privilege escalation chains

### Firewall detectors

- Port scan
- SYN flood
- SSH brute force indicators
- Egress exfiltration indicators

### ML detectors

- Isolation Forest anomaly detection
- Supervised IP classification (RandomForest)

## Project structure

- `main.py`: application entry point
- `whiskers.py`: core runtime controller and pipeline orchestration
- `command_processing.py`: CLI argument/command handling
- `parser/log_parser.py`: parsing and source-specific normalization
- `analysis/feature_engineering.py`: feature generation for detection
- `analysis/ml_steps.py`: model loading and ML scoring flow
- `analysis/train_supervised_ip_classifier.py`: supervised model training script
- `detectors/`: per-threat detector implementations
- `detectors/registry.py`: detector construction and source-based selection
- `GUI/main_window.py`: PyQt main window
- `GUI/pages/`: GUI pages/components
- `simulator/`: synthetic log generation tools
- `models/`: serialized model artifacts (`.joblib`)

## Setup

```bash
python -m venv .venv
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
```

## Running Whiskers

### CLI quick start

```bash
python main.py [options]
```

### Important: CLI runs, then REPL

When you pass startup flags (like `-d`, `-g`, `-c`, etc.), Whiskers **runs the requested actions first** and then **drops into the interactive REPL** (`await_input`) for further commands.

- Quit the REPL with **`q`**, **`quit`**, **`exit`**, **`-q`**, **`--quit`**, or **`--exit`**.

### Generate logs

```bash
# Generate all default log types
python main.py -g

# Generate specific types
python main.py -gac -gauth -gfire

# Per-log custom sizes
python main.py -gac -gauth -s 1000 500
```

### Run detection

```bash
# Detect on configured/default logs
python main.py -d

# Detect specific families
python main.py -dac -dauth

# Use explicit files
python main.py -d -al /path/to/access.log -au /path/to/auth.log

# Verbose alert output
python main.py -d -v
```

### Check and stats

```bash
# Compare true vs detected attack counts
python main.py -c

# Show generated actor profile distribution
python main.py -as
```

### GUI mode

```bash
python main.py -ui
```

### Interactive mode

```bash
python main.py
# Then enter commands interactively
```

## CLI options reference

```text
General:
-h, --help                      Show help
-ui, --ui                       Open graphical user interface
q, quit, exit, -q, --quit       Close Whiskers (interactive mode)
--exit                          Alias for quit/exit

Generation:
-gac, --generate_access         Generate access log (data/access.log)
-gauth, --generate_auth         Generate auth log (data/auth.log)
-gfire, --generate_firewall     Generate firewall log (data/firewall.log)
-g, --generate                  Generate all configured log types
-s, --size [NUM ...]            Generation size value(s) (default: 2000)
                                Provide 1+ positive integers after -s/--size.
                                - If you provide 1 value, it applies to all selected generation flags.
                                - If you provide multiple values, you must provide exactly one per selected
                                  generation flag, in the same order as the generation flags were given
                                  (e.g. `-gac -gauth -s 1000 500` maps access=1000, auth=500).

Detection:
-d, --detect                    Run detection on current logs
-dac, --detect_access           Detect access logs
-dauth, --detect_auth           Detect auth logs
-dfw, --detect_firewall         Detect firewall logs
-v, --verbose                   Print detailed alert output
-al, --access-log [PATH]        Use custom access log file
-au, --auth-log [PATH]          Use custom auth log file
-fw, --firewall-log [PATH]      Use custom firewall log file (PATH flag)

Checking:
-c, --check                     Compare generated-vs-detected attacks
-as, --actor-stats              Show actor profile distribution

File management commands:
save [log_type] [filename] [directory(optional)]
shred [log_type]
```

## Model artifacts

- `models/ip_supervised_rf.joblib` (bundle with model + feature schema + metadata)
- `models/ip_supervised_rf.joblib.sha256` (required integrity file; must match the `.joblib` SHA-256)

Models are only loaded from **within the `models/` directory** (Whiskers refuses paths that resolve outside `models/`).

Training script: `analysis/train_supervised_ip_classifier.py`
- Trains from whichever of `data/access.log`, `data/auth.log`, `data/firewall.log` exist.
- Requires both normal and malicious IPs in the dataset.

## Safety & file operations

Whiskers includes file operations for convenience, with guardrails:

- **`save`**: copies the *currently configured* log source for `access` / `auth` / `firewall` to a destination path.
  - The destination is constrained to stay within the Whiskers project root for relative paths (path traversal like `..` is rejected).
  - In the interactive REPL, `save` requires typing **`yes`** to confirm (to reduce accidental overwrites).
- **`shred`**: permanently deletes the *currently configured* source log file for the given `log_type`.
  - `shred` ignores extra filename/directory arguments; it targets the configured source path for that log type.
  - In the interactive REPL, `shred` requires typing **`yes`** to confirm (cannot be undone).

## Notes

- The mouse/"Whiskers" theme is intentional for fun and branding.
- Roadmap items should stay scoped to incremental, testable improvements.
