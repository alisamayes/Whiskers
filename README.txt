# Whiskers

Whiskers is a learning-focused cybersecurity log analysis toolkit combining rule-based threat detection with machine learning on server logs.
The project is built for learning and demonstration rather than production real-time defense.

---

## Goals

- Improve Python engineering and code organization
- Explore cyber threat detection techniques
- Combine rule-based detection with ML anomaly and classification models
- Build on Apache-style log parsing and make improvements for more sources

---

## What Whiskers does

- **Parse multiple log formats** into structured data:
  - Apache access logs
  - Linux auth logs
  - Firewall logs (WIP)
- **Generate synthetic logs** for testing and learning
- **Apply threat detectors** for:
  - Brute force attacks
  - Directory traversal/scanning
  - Request flood / DDoS patterns
  - SQL Injection
  - Command Injection
  - Data exfiltration
  - SSH bruteforce and user enumeration
  - Sudo bruteforce
  - Privilege escalation chains
- **Run ML models** to score IPs and connections:
  - Anomaly detection via IsolationForest
  - Supervised IP classification via RandomForest
- **Output suspicious IP reports** + flags for detected threat types
- **Check detection accuracy** against known attack patterns
- **Interactive CLI** and **GUI interface**

---

## Current supported log formats

- Apache access logs (combined/standard)
- Linux auth logs (auth.log/secure)
- Firewall logs (experimental)

---

## Threat categories

### Implemented
- **Access log threats:**
  - Brute force
  - Directory traversal/scanning
  - Request flood / DDoS
  - SQL injection
  - Command injection
  - Data exfiltration

- **Auth log threats:**
  - SSH bruteforce
  - SSH user enumeration
  - Sudo bruteforce
  - Privilege escalation chains

- **ML-based detection:**
  - Isolation Forest anomaly detection
  - Supervised IP classification

### Planned
- Geo-location based anomalies
- Insecure Direct Object References (IDOR)
- OWASP Top 10 coverage expansion

---

## Project structure

- `main.py`: application entry point
- `whiskers.py`: main controller logic (input → detect → output)
- `command_processing.py`: CLI command parsing and execution
- `parser/log_parser.py`: log ingestion and DataFrame normalization
- `analysis/feature_engineering.py`: builds detection features
- `analysis/threat_detection.py`: orchestrates detectors
- `analysis/ml_steps.py`: ML pipeline, model load/score
- `analysis/train_supervised_ip_classifier.py`: train classifier
- `analysis/detectors/`: per-threat detector modules
- `GUI/main_window.py`: PyQt GUI window
- `simulator/`: log generation and simulation tools
  - `log_simulator.py`: core generation logic
  - `access_log_simulator.py`: access log generation
  - `auth_log_simulator.py`: auth log generation
  - `log_manager.py`: log file management utilities
- `models/`: saved `.joblib` model files

---

## Run instructions

### 1. Set up environment
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. CLI mode

#### Basic usage
```bash
python main.py [options]
```

#### Generate logs
```bash
# Generate default logs (2000 actions each)
python main.py -g

# Generate specific log types
python main.py -gac -gauth -gfire

# Generate with custom sizes (per log type)
python main.py -gac -gauth -s 1000 500
```

#### Run detection
```bash
# Detect on all default logs
python main.py -d

# Detect on specific logs
python main.py -dac -dauth

# Use custom log files
python main.py -d -al /path/to/access.log -au /path/to/auth.log

# Verbose output
python main.py -d -v
```

#### Check accuracy
```bash
python main.py -c
```

#### Show actor statistics
```bash
python main.py -as
```

#### Log management
```bash
# Save current log
python main.py save my_log.log

# Delete a log file
python main.py shred old_log.log
```

### 3. GUI mode
```bash
python main.py -ui
```

### 4. Interactive mode
```bash
python main.py
# Then enter commands interactively
```

---

## CLI Options Reference

```
General:
-h, --help                      Show this help message
-ui, --ui                       Open the graphical user interface
q, quit, exit                   Close Whiskers

Generation:
-gac, --generate_access         Generate new access log (data/access.log)
-gauth, --generate_auth         Generate new auth log (data/auth.log)
-gfire, --generate_firewall     Generate new firewall log (data/firewall.log)
-g, --generate                  Generate all log types
-s, --size [numbers]            Number of actions actors will take to generate logs
                                (default 2000, attacks generate more lines)
                                Multiple values for per-log-type sizing

Detection:
-d, --detect                    Run detection on all current logs
-dac, --detect-access           Run detection on access.log only
-dauth, --detect-auth           Run detection on auth.log only
-v, --verbose                   Enable verbose detection output
-al, --access-log [PATH]        Use specific access log file
-au, --auth-log [PATH]          Use specific auth log file
-fw, --firewall-log [PATH]      Use specific firewall log file (WIP)

Checking:
-c, --check                     Check detection accuracy
-as, --actor-stats              Show actor profile distribution

Log management:
save [log_type] [filename] [directory]
                                Save currently configured access/auth/firewall
                                source log to new file
shred [filename] [directory]    Delete log file
```

---

## Model artifacts

- `models/isolation_forest.joblib`: Isolation Forest anomaly detection model
- `models/isolation_scaler.joblib`: Feature scaler for isolation forest
- `models/ip_supervised_rf.joblib`: Supervised IP classification model

Training script: `analysis/train_supervised_ip_classifier.py`

---

## Project board

https://app.plane.so/whiskers/projects/bd4260e8-7da4-4145-b35c-767f3a9e115d/issues/

- `models/isolation_forest.joblib`
- `models/isolation_scaler.joblib`
- `models/ip_supervised_rf.joblib`

Training script: `analysis/train_supervised_ip_classifier.py`

---

## Notes

- The mouse/"Whiskers" theme is intentional for fun and branding.
---
