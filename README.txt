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

- Parse Apache-style access logs into structured data
- Apply threat detectors for:
  - Brute force
  - Directory traversal
  - Request flood / DDoS patterns
  - SQL Injection
  - Data exfiltration
- Run ML models to score IPs and connections
  - Anomaly detection via IsolationForest
  - Supervised IP classification via RandomForest / classifier
- Output suspicious IP report + flags for detected threat types

---

## Current supported log format

- Apache access logs (combined/standard)

### Planned additions

- Firewall logs
- Network IP logs
- Custom ingestion pipeline

---

## Threat categories

### Implemented
- Brute force
- Directory traversal
- Request flood / DDoS
- SQL injection
- Exfiltration

### Planned
- Geo-location based anomalies
- Insecure Direct Object References (IDOR)
- OWASP Top 10 coverage

---

## Project structure

- `main.py`: application entry
- `whiskers.py`: controller logic (input → detect → output)
- `parser/log_parser.py`: log ingestion and DataFrame normalization
- `analysis/feature_engineering.py`: builds detection features
- `analysis/threat_detection.py`: orchestrates detectors
- `analysis/ml_steps.py`: ML pipeline, model load/score
- `analysis/train_supervised_ip_classifier.py`: train classifier
- `analysis/detectors/`: per-threat detector modules
- `GUI/main_window.py`: PyQt GUI window
- `simulator/`: log generation and simulation tools
- `models/`: saved `.joblib` model files

---

## Run instructions

### 1. Set up environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. CLI mode
```bash
python main.py path/to/access.log
```

### 3. GUI mode
```bash
python main.py
```


---

## Model artifacts

- `models/isolation_forest.joblib`
- `models/isolation_scaler.joblib`
- `models/ip_supervised_rf.joblib`

Training script: `analysis/train_supervised_ip_classifier.py`

---

## Notes

- The mouse/"Whiskers" theme is intentional for fun and branding.
- This repo can evolve into a dashboard plus active response simulation.

---

## Project board

https://app.plane.so/whiskers/projects/bd4260e8-7da4-4145-b35c-767f3a9e115d/issues/
