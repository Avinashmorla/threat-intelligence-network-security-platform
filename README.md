# Threat Intelligence & Network Security Analysis Platform

A lightweight, educational **log-based threat detection and investigation platform** built with **Python, SQLite, SQL, and Bash**.

The project analyzes security logs from multiple sources, applies rule-based detection techniques to identify suspicious activity, stores detected events as structured security findings, allows investigation of suspicious sources, and generates an incident report.

The platform demonstrates a simplified **Security Operations Center (SOC) workflow**:

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

> **Note:** This project performs log analysis only. It does not perform packet capture, live network sniffing, operate real SSH/SMTP servers, or connect to AWS/GuardDuty.

---

## Features

- Multi-source security log analysis
- SSH brute-force detection
- DNS anomaly / possible DNS tunneling detection
- SQL injection detection
- Path traversal detection
- SMTP abuse detection
- Cloud/API anomaly detection
- Severity classification
- Structured security findings
- SQLite-based threat-data storage
- SQL-based investigation
- Source/IP investigation
- Automated incident report generation
- Bash-based pipeline automation

---

## Project Structure

```text
threat-intel-platform/
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
└── README.md
```

### Main Components

**`detectors.py`**

Contains the log-parsing logic and the five threat-detection rules. Each detector analyzes a specific type of security event and produces a standardized finding.

**`detect.py`**

Acts as the main detection pipeline. It runs all detectors, stores the resulting findings in the SQLite database, and displays security alerts in the terminal.

**`investigate.py`**

Allows investigation of a specific source IP or sender and displays the associated findings, evidence, and recommended action.

**`report.py`**

Reads the findings database and generates a text-based security report containing statistics, suspicious sources, incidents, evidence, and recommended actions.

**`queries.sql`**

Contains SQL queries for manually investigating the stored security findings.

**`run.sh`**

Automates the complete workflow by checking the input files, running detection, and generating the report.

---

## Log Sources

The platform works with five types of security data:

| Source | Purpose |
|---|---|
| `auth.log` | Authentication and login activity |
| `dns.log` | DNS queries |
| `http.log` | HTTP/web requests |
| `smtp.log` | Email activity |
| `cloud_events.json` | Cloud/API security events |

The included data consists of small synthetic security logs containing mostly normal activity along with selected attack patterns.

---

## Threat Detection

Each detector applies a simple and explainable rule to its corresponding log source.

### SSH Brute Force

Authentication failures are grouped by source IP.

If a single IP produces **10 or more failed login attempts**, it is classified as:

```text
Threat Type: SSH_BRUTE_FORCE
Severity: HIGH
```

The finding includes the number of attempts and usernames targeted.

### DNS Anomaly

DNS queries are grouped by source IP and base domain.

If a source generates **15 or more unique subdomains** for the same domain, it is flagged as a possible DNS tunneling or data-exfiltration pattern.

```text
Threat Type: DNS_ANOMALY
Severity: MEDIUM
```

This is a heuristic detection and does not prove that DNS tunneling is occurring.

### Web Injection

HTTP request paths are checked for common attack patterns.

The detector looks for patterns associated with:

- SQL injection
- Path traversal

Examples include:

```text
' OR 1=1
UNION SELECT
../
/etc/passwd
```

SQL injection is mapped to **OWASP A03:2021 - Injection**, while path traversal is mapped to **OWASP A01:2021 - Broken Access Control**.

These findings are classified as:

```text
Threat Type: WEB_INJECTION
Severity: HIGH
```

### SMTP Abuse

Email activity is grouped by sender.

If one sender targets **more than 20 recipients**, the activity is classified as possible spam, compromised-mailbox activity, or messaging abuse.

```text
Threat Type: SMTP_ABUSE
Severity: MEDIUM
```

### Cloud/API Anomaly

Cloud events are provided as local JSON data.

The detector identifies events such as:

- Failed console logins
- Sensitive API actions
- Security-control tampering

Examples of sensitive actions include:

```text
CreateAccessKey
PutUserPolicy
DeleteTrail
StopLogging
AuthorizeSecurityGroupIngress
```

These events produce:

```text
Threat Type: CLOUD_API_ANOMALY
Severity: MEDIUM / HIGH
```

The cloud component is a **local simulation of GuardDuty-style findings** and does not connect to an AWS account or API.

---

## Security Findings

All detectors produce findings using a common structure:

```text
timestamp
threat_type
severity
source
description
evidence
```

This allows different types of security events to be stored and investigated consistently.

For example:

```text
SSH_BRUTE_FORCE
HIGH
203.0.113.77
Multiple failed authentication attempts
```

---

## SQLite Database

Detected findings are stored in a SQLite database named:

```text
findings.db
```

The database contains a `findings` table:

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

SQLite was chosen because the project uses a small local dataset and does not require a separate database server.

Each detection run refreshes the findings so that the database reflects the current input logs.

---

## Investigation

The project supports investigation of a specific source.

For example:

```bash
python investigate.py 203.0.113.77
```

The investigation performs a source-based database query and displays:

- Detected threats
- Severity
- Evidence
- Description
- Recommended action

This represents a simplified:

```text
Detection → Finding → Evidence → Investigation → Recommendation
```

workflow.

---

## SQL Investigation

The `queries.sql` file provides SQL queries for investigating the findings database.

The queries cover:

- All findings
- High-severity findings
- Findings grouped by threat type
- Findings grouped by source
- Most suspicious sources

Example:

```sql
SELECT *
FROM findings
WHERE severity = 'HIGH';
```

If the SQLite CLI is installed:

```bash
sqlite3 findings.db < queries.sql
```

---

## Incident Reporting

After detection, `report.py` can generate:

```text
report.txt
```

The report includes:

- Total findings
- Findings by severity
- Findings by threat type
- Top suspicious sources
- Detailed incidents
- Evidence
- Recommended actions

Run:

```bash
python report.py
```

This provides a simple security review report that can be used to summarize the detected activity.

---

## How to Run

### Windows PowerShell

Run the components individually:

```powershell
python detect.py
python report.py
python investigate.py 203.0.113.77
```

### Linux / macOS / WSL / Git Bash

The complete workflow can be automated using:

```bash
chmod +x run.sh
./run.sh
```

The script performs:

```text
1. Check input logs
2. Run threat detection
3. Generate security report
```

---

## Technologies Used

- **Python** — Log parsing, detection rules, investigation, and reporting
- **SQLite** — Structured security-finding storage
- **SQL** — Threat-data investigation and analysis
- **Bash** — Pipeline automation
- **JSON** — Cloud/API event representation
- **Git** — Version control

---

## Project Workflow

The complete platform follows this workflow:

```text
                ┌─────────────────┐
                │   Security Logs │
                └────────┬────────┘
                         ↓
                ┌─────────────────┐
                │  Python Parser  │
                └────────┬────────┘
                         ↓
                ┌─────────────────┐
                │ Detection Rules │
                └────────┬────────┘
                         ↓
                ┌─────────────────┐
                │ Security        │
                │ Findings        │
                └────────┬────────┘
                         ↓
                ┌─────────────────┐
                │ SQLite Database │
                └───────┬─────────┘
                        ↓
             ┌──────────┴──────────┐
             ↓                     ↓
      SQL Investigation      Source Investigation
             │                     │
             └──────────┬──────────┘
                        ↓
                ┌─────────────────┐
                │ Incident Report │
                └─────────────────┘
```

---

## Limitations

This project intentionally uses simple, explainable detection rules.

It does **not** currently provide:

- Real-time log streaming
- Packet-level network analysis
- Machine-learning detection
- Production SIEM functionality
- Real AWS/GuardDuty integration
- Automated blocking or firewall actions
- External threat-intelligence feeds

The project is designed to demonstrate the core concepts of **security log analysis, threat detection, investigation, SQL analysis, automation, and security reporting**.

---

## Future Improvements

Possible extensions include:

- Real-time log ingestion
- Configurable detection thresholds
- Allow-lists to reduce false positives
- Additional OWASP detection rules
- Time-window based detection
- Threat-intelligence API integration
- SIEM integration
- Web-based security dashboard
- AWS CloudTrail/GuardDuty integration
- Unit testing for detection rules
- HTML/PDF report generation
- Machine-learning based anomaly detection
