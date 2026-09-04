# Threat Intelligence & Network Security Analysis Platform

A lightweight **security log analysis and threat detection platform** built with **Python, SQLite, SQL, and Bash**.

The project simulates a small SOC-style detection workflow. It ingests security events from authentication, DNS, HTTP, SMTP, and cloud/API logs, applies explainable rule-based detection, converts suspicious activity into structured findings, stores them in SQLite, supports source-level investigation, and generates an incident report.

## Architecture

```text
                    ┌──────────────────────┐
                    │     Security Logs     │
                    ├──────────────────────┤
                    │ auth.log              │
                    │ dns.log               │
                    │ http.log              │
                    │ smtp.log              │
                    │ cloud_events.json     │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │     detectors.py     │
                    │                      │
                    │  • Log Parsing       │
                    │  • Threat Detection  │
                    │  • Severity          │
                    │  • Evidence          │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │      detect.py       │
                    │   Detection Pipeline  │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │    findings.db       │
                    │       SQLite         │
                    └──────────┬───────────┘
                               │
                    ┌──────────┴──────────┐
                    │                     │
                    ▼                     ▼
           ┌─────────────────┐   ┌─────────────────┐
           │  queries.sql    │   │ investigate.py  │
           │ SQL Investigation│   │ Source Analysis │
           └────────┬────────┘   └────────┬────────┘
                    │                     │
                    └──────────┬──────────┘
                               ▼
                    ┌──────────────────────┐
                    │      report.py       │
                    │  Incident Reporting  │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │     report.txt       │
                    └──────────────────────┘

                    run.sh
        Automates the complete pipeline
```

## What the Project Does

The platform takes raw security logs and transforms them into actionable security findings.

```text
Raw Security Event
        ↓
Parse Event
        ↓
Apply Detection Rule
        ↓
Classify Severity
        ↓
Create Finding
        ↓
Store in SQLite
        ↓
Investigate
        ↓
Generate Report
```

Every finding follows a common structure:

```text
timestamp
threat_type
severity
source
description
evidence
```

This allows findings from completely different log sources to be stored and investigated consistently.

---

## Detection Capabilities

| Log Source | Detection | Rule | Severity |
|---|---|---|---|
| `auth.log` | SSH Brute Force | ≥10 failed logins from one IP | HIGH |
| `dns.log` | DNS Anomaly | ≥15 unique subdomains from one IP/domain | MEDIUM |
| `http.log` | SQL Injection | Detects common SQL injection patterns | HIGH |
| `http.log` | Path Traversal | Detects traversal patterns such as `../` and `/etc/passwd` | HIGH |
| `smtp.log` | SMTP Abuse | Sender targets >20 recipients | MEDIUM |
| `cloud_events.json` | Cloud/API Anomaly | Failed logins and sensitive API actions | MEDIUM/HIGH |

### SSH Brute Force

Failed authentication attempts are grouped by source IP.

When an IP reaches the configured threshold of **10 or more failures**, the activity is classified as `SSH_BRUTE_FORCE`.

The finding records the source, number of attempts, targeted usernames, and supporting evidence.

### DNS Anomaly

DNS queries are grouped by **source IP and base domain**.

A source generating **15 or more unique subdomains** for the same domain is flagged as a possible DNS tunneling or data-exfiltration pattern.

This is a heuristic and does not by itself prove malicious activity.

### Web Attack Detection

HTTP request paths are inspected for common attack strings.

The detector identifies:

- SQL injection
- Path traversal

Examples include:

```text
' OR 1=1
UNION SELECT
../
/etc/passwd
```

SQL injection is associated with **OWASP A03:2021 - Injection**, while path traversal is associated with **OWASP A01:2021 - Broken Access Control**.

### SMTP Abuse

Email activity is grouped by sender.

A sender targeting more than **20 recipients** is flagged as potential spam, compromised-mailbox activity, or messaging abuse.

### Cloud/API Anomaly

Cloud events are represented as local JSON data.

The detector looks for suspicious activity such as:

- Failed console logins
- `CreateAccessKey`
- `PutUserPolicy`
- `DeleteTrail`
- `StopLogging`
- `AuthorizeSecurityGroupIngress`

This component is a **local simulation of GuardDuty-style detection** and does not connect to AWS.

---

## Project Structure

```text
threat-intel-platform/
│
├── data/
│   ├── auth.log
│   ├── dns.log
│   ├── http.log
│   ├── smtp.log
│   └── cloud_events.json
│
├── detectors.py
├── detect.py
├── investigate.py
├── report.py
├── queries.sql
├── run.sh
├── .gitignore
├── .gitattributes
└── README.md
```

### Core Components

**`detectors.py`**

Contains the log parsers and individual threat-detection functions. Each detector returns findings using the same structure.

**`detect.py`**

Runs the complete detection pipeline, executes all detectors, creates/updates the SQLite database, stores findings, and displays alerts.

**`investigate.py`**

Investigates a particular source IP or sender by querying all associated findings and displaying their evidence and recommended actions.

**`queries.sql`**

Provides SQL queries for security investigation, including high-severity findings, threat counts, source counts, and suspicious sources.

**`report.py`**

Analyzes the findings database and generates a human-readable `report.txt` containing security findings, statistics, evidence, and recommendations.

**`run.sh`**

Automates the complete workflow:

```text
Check Input Files
       ↓
Run Detection
       ↓
Generate Report
```

---

## Data Storage

Detected events are stored in a SQLite database:

```text
findings.db
```

The database contains a single `findings` table:

```sql
CREATE TABLE findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT,
    threat_type TEXT,
    severity    TEXT,
    source      TEXT,
    description TEXT,
    evidence    TEXT
);
```

SQLite was selected because the project uses a small local dataset and does not require a separate database server.

---

## Investigation

Once suspicious activity has been detected, a specific source can be investigated.

Example:

```bash
python investigate.py 203.0.113.77
```

The investigation retrieves findings associated with that source and displays:

- Threat type
- Severity
- Description
- Evidence
- Recommended action

This provides a simple incident-response workflow:

```text
Detection
    ↓
Finding
    ↓
Evidence
    ↓
Source Investigation
    ↓
Recommended Action
```

---

## SQL Analysis

The `queries.sql` file provides investigation queries for the findings database.

It includes queries for:

- All security findings
- HIGH-severity findings
- Findings grouped by threat type
- Findings grouped by source
- Top suspicious sources

Example:

```sql
SELECT *
FROM findings
WHERE severity = 'HIGH';
```

If the SQLite CLI is available:

```bash
sqlite3 findings.db < queries.sql
```

---

## Incident Reporting

After detection, the project can generate a security report:

```bash
python report.py
```

Output:

```text
report.txt
```

The report summarizes:

- Total findings
- Severity distribution
- Threat types
- Suspicious sources
- Detailed incidents
- Evidence
- Recommended actions

This provides a simple security-review artifact from the detected activity.

---

## Installation & Usage

### Requirements

- Python 3.x
- Bash for `run.sh`
- SQLite CLI is optional

The Python implementation uses standard-library modules and does not require external packages.

### Windows PowerShell

Run the pipeline step by step:

```powershell
python detect.py
python investigate.py 203.0.113.77
python report.py
```

### Linux / macOS / WSL / Git Bash

Run the complete pipeline:

```bash
chmod +x run.sh
./run.sh
```

Or run the components individually:

```bash
python detect.py
python investigate.py 203.0.113.77
python report.py
```

---

## Technologies

- **Python** — Log parsing, detection, investigation, and reporting
- **SQLite** — Structured security-finding storage
- **SQL** — Threat investigation and analysis
- **Bash** — Pipeline automation
- **JSON** — Cloud/API event representation
- **Git** — Version control

---

## Design Approach

The project intentionally uses **simple, deterministic, and explainable detection rules**.

Instead of treating detection as a black box, every finding can be traced back to:

```text
Input Log
    ↓
Detection Rule
    ↓
Finding
    ↓
Evidence
    ↓
Investigation
    ↓
Recommendation
```

This makes the detection logic easy to understand, test, investigate, and extend.

Adding another detector can follow the same pattern:

```text
New Log Source
      ↓
New detect_*() function
      ↓
Standard Finding
      ↓
SQLite
      ↓
Existing Investigation & Reporting
```

---

## Limitations

This is an educational/local security-analysis platform and is not intended to replace a production SIEM or IDS.

It currently does not provide:

- Real-time log streaming
- Packet capture or network sniffing
- Machine-learning detection
- Production SIEM functionality
- Real AWS/GuardDuty integration
- External threat-intelligence feeds
- Automated firewall/blocking actions
- Real SSH or SMTP servers

The cloud-security component is a **local simulation**, and the included logs are synthetic.

---

## Future Improvements

- Real-time log ingestion
- Configurable detection thresholds
- Time-window based detection
- Allow-lists for reducing false positives
- Additional OWASP detection rules
- Threat-intelligence API integration
- SIEM integration
- AWS CloudTrail/GuardDuty integration
- Web-based security dashboard
- Automated alerting
- Unit tests for detection rules
- HTML/PDF security reports

---

## Project Goal

The goal of this project is to demonstrate a complete, understandable security-analysis pipeline that connects **log analysis, threat detection, structured security data, SQL investigation, incident investigation, automation, and reporting** in a single project.

```text
Collect → Parse → Detect → Store → Investigate → Report
```
