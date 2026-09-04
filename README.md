# Threat Intelligence & Network Security Analysis Platform

A lightweight, educational log-based threat detection pipeline built with **Python, SQLite, SQL, and Bash**.

It analyzes security logs from authentication, DNS, HTTP, SMTP, and cloud/API sources, applies rule-based threat detection, stores findings in SQLite, supports source investigation, and generates a security report.

> **Note:** This project performs log analysis only. It does not perform packet capture, live network sniffing, real SSH/SMTP operations, or real AWS/GuardDuty integration.

## Features

- SSH brute-force detection
- DNS anomaly / tunneling detection
- SQL injection detection
- Path traversal detection
- SMTP abuse detection
- Cloud/API anomaly detection
- SQLite-based security findings
- SQL investigation queries
- Source/IP investigation
- Automated incident report generation
- Bash pipeline automation

## Project Structure

```text
threat-intel-platform/
├── data/
│   ├── auth.log
│   ├── dns.log
│   ├── http.log
│   ├── smtp.log
│   └── cloud_events.json
├── detectors.py
├── detect.py
├── investigate.py
├── report.py
├── queries.sql
├── run.sh
└── README.md
```

## Detection Rules

| Threat | Detection |
|---|---|
| SSH Brute Force | ≥10 failed logins from one IP |
| DNS Anomaly | ≥15 unique subdomains from one IP/domain |
| SQL Injection | Common SQL injection patterns |
| Path Traversal | Directory traversal patterns |
| SMTP Abuse | Sender targeting >20 recipients |
| Cloud/API Anomaly | Failed logins and sensitive API actions |

## How to Run

### Windows PowerShell

```powershell
python detect.py
python report.py
python investigate.py 203.0.113.77
```

### Linux / macOS / WSL / Git Bash

```bash
chmod +x run.sh
./run.sh
```

### SQL Investigation

```bash
sqlite3 findings.db < queries.sql
```

## Technologies

- **Python** — Log parsing and threat detection
- **SQLite** — Finding storage
- **SQL** — Security investigation
- **Bash** — Automation
- **JSON** — Cloud/API event data
- **Git** — Version control

## Workflow

```text
Security Logs
     ↓
Log Parsing
     ↓
Threat Detection
     ↓
Security Findings
     ↓
SQLite Database
     ↓
Investigation
     ↓
Incident Report
```

## Future Improvements

- Real-time log ingestion
- Threat-intelligence API integration
- SIEM integration
- Web-based security dashboard
- AWS CloudTrail/GuardDuty integration
- Machine-learning based anomaly detection

## Security Note

This is an **educational/local security analysis project** using sample logs and rule-based detection. The cloud security component is a local simulation and does not connect to AWS.
