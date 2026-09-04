# Threat Intelligence & Network Security Analysis Platform

A small, honest, educational version of a log-based threat-detection pipeline.

It reads security **log files** (authentication, DNS, HTTP, SMTP, cloud/API),
applies simple **Python detection rules**, stores the results as **findings** in a
**SQLite** database, lets you **investigate** a suspicious source, and generates a
**text incident report**. **Bash** automates the whole run.

> This is **log analysis only**. There is **no** packet capture, no live network
> sniffing, no real SSH/SMTP server, and no real AWS/GuardDuty connection.

---

## 1. Directory structure

```
threat-intel-platform/
├── data/
│   ├── auth.log            # login attempts   (timestamp | status | user | ip)
│   ├── dns.log             # DNS queries       (timestamp | ip | query | type)
│   ├── http.log            # web requests      (timestamp | ip | method | path | status)
│   ├── smtp.log            # email sends       (timestamp | sender | ip | recipient)
│   └── cloud_events.json   # cloud/API events  (JSON list)
├── detectors.py            # parsing + the 5 detection rules
├── detect.py               # main pipeline: run detectors -> SQLite -> alerts
├── investigate.py          # incident investigation for one source
├── report.py               # build report.txt from findings.db
├── queries.sql             # 5 SQL investigation queries
├── run.sh                  # Bash automation of the pipeline
├── README.md               # this file
├── findings.db             # SQLite DB (created when you run detect.py)
└── report.txt              # report (created when you run report.py)
```

## 2. Every file and its purpose

| File | Purpose |
|---|---|
| `data/*.log`, `cloud_events.json` | Small synthetic logs with mostly-normal traffic + a few planted attacks |
| `detectors.py` | Parsing helper + one function per threat; thresholds and recommended actions live here |
| `detect.py` | Runs all detectors, wipes/refills `findings.db`, prints console alerts |
| `investigate.py` | `python investigate.py <ip>` → all findings + evidence + recommendation for that source |
| `report.py` | Reads the DB and writes/print `report.txt` |
| `queries.sql` | Copy-paste SQL for manual investigation |
| `run.sh` | Checks inputs → runs detection → generates report |

## 3. Exact commands to run

Requires **Python 3** only (uses the standard library — `sqlite3`, `json`, `collections`).

**On Linux / macOS / WSL / Git Bash (full automation):**
```bash
cd threat-intel-platform
chmod +x run.sh
./run.sh
```

**On any OS, step by step:**
```bash
python detect.py                 # detect threats -> findings.db + console alerts
python report.py                 # build and print report.txt
python investigate.py 203.0.113.77   # investigate one source
```

**On Windows PowerShell (no Bash needed):**
```powershell
python detect.py
python report.py
python investigate.py 203.0.113.77
```

**Query the database directly (if you have the `sqlite3` CLI):**
```bash
sqlite3 findings.db < queries.sql
sqlite3 findings.db "SELECT * FROM findings WHERE severity='HIGH';"
```

## 4. Complete execution flow

```
data/*.log ──▶ detectors.py (parse + rule) ──▶ list of finding dicts
                                                     │
                              detect.py ────────────▶ findings.db (SQLite)
                                                     │      │
                                        console alerts      ▼
                                              queries.sql / investigate.py  (SQL investigation)
                                                            │
                                                        report.py ──▶ report.txt
run.sh runs steps 1→3 automatically.
```

## 5. Explanation of every threat detector

Each detector returns findings with the same shape:
`{ timestamp, threat_type, severity, source, description, evidence }`.

| # | Input log | Rule | Threat type | Severity |
|---|---|---|---|---|
| 1 | `auth.log` | One IP with **≥ 10 FAILURE** logins | `SSH_BRUTE_FORCE` | HIGH |
| 2 | `dns.log` | One IP with **≥ 15 unique subdomains** of one domain | `DNS_ANOMALY` | MEDIUM |
| 3 | `http.log` | Path contains **SQLi** (`' OR 1=1`, `UNION SELECT`) or **traversal** (`../`, `/etc/passwd`) | `WEB_INJECTION` | HIGH |
| 4 | `smtp.log` | One sender to **> 20 recipients** | `SMTP_ABUSE` | MEDIUM |
| 5 | `cloud_events.json` | **Failed console login**, or a **sensitive API action** (`CreateAccessKey`, `StopLogging`, …) | `CLOUD_API_ANOMALY` | MEDIUM / HIGH |

- **SSH_BRUTE_FORCE** — group failures by source IP, count them, flag if the count crosses the threshold. Evidence lists the count and the usernames that were tried.
- **DNS_ANOMALY** — group unique query names by `(source IP, base domain)`. A host asking for hundreds of random subdomains of one domain is the classic **DNS tunneling / data exfiltration** signature.
- **WEB_INJECTION** — plain substring match for known attack strings, mapped to the relevant **OWASP Top 10** category (A03 Injection, A01 Broken Access Control). Simple and explainable — not a full WAF.
- **SMTP_ABUSE** — count recipients per sender; a single sender blasting many recipients is a spam / compromised-mailbox / **messaging-abuse** indicator.
- **CLOUD_API_ANOMALY** — a **local simulation of GuardDuty-style findings**: failed logins and tampering actions (creating keys, stopping CloudTrail logging) become findings. No AWS account or API is used.

## 6. Explanation of the SQLite database

One table, created by `detect.py`:

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

SQLite is a single file (`findings.db`) — no server to install. Each run clears and
refills the table so results always match the current logs. This demonstrates
**structured threat-data storage** so it can be queried with SQL.

## 7. Explanation of the SQL queries (`queries.sql`)

1. **All findings** — full list ordered by time.
2. **HIGH severity only** — `WHERE severity = 'HIGH'` — triage first.
3. **Count by threat type** — `GROUP BY threat_type` — what kind of attacks dominate.
4. **Count by source** — `GROUP BY source` — which IP/sender is noisiest.
5. **Most suspicious sources** — `GROUP BY source ... ORDER BY total DESC LIMIT 5` — top offenders.

These use only `SELECT`, `WHERE`, `GROUP BY`, `COUNT`, `ORDER BY`, `HAVING`, `LIMIT` —
easy to explain in an interview.

## 8. Explanation of the Bash automation (`run.sh`)

Demonstrates real shell scripting: `set -e` (fail fast), `cd "$(dirname "$0")"`
(run from anywhere), a `for` loop with `[ -f "$f" ]` file checks, `wc -l` line counts,
running Python, and clean exit codes (`exit 1` on missing input). Three steps:
**check inputs → run detection → generate report.**

## 9. Explanation of incident investigation (`investigate.py`)

`python investigate.py <source>` runs
`SELECT * FROM findings WHERE source = ?` and prints, for that IP/sender, every
finding with its evidence and the recommended action. This is the
**Detection → Finding → Evidence → Investigation → Recommendation** workflow at the
command line.

## 10. Explanation of report generation (`report.py`)

Reads `findings.db` and produces `report.txt`: total findings, counts by severity,
counts by type, top suspicious sources, and a detailed incident list with evidence
and recommended actions — a plain-text **security review report** for technical and
non-technical readers.

## 11. Resume → project feature mapping

| Resume phrase | Where it lives in this project |
|---|---|
| Python data-analysis pipeline | `detect.py` + `detectors.py` |
| Security log analysis / threat-pattern identification | all 5 detectors over `data/*` |
| Unauthorized access detection | `detect_auth` → `SSH_BRUTE_FORCE` |
| Anomalous API calls | `detect_cloud` → `CLOUD_API_ANOMALY` |
| Messaging abuse detection | `detect_smtp` → `SMTP_ABUSE` |
| SQL-based threat-data analysis | `findings` table + `queries.sql` |
| Linux/Unix investigation | grep/cat/wc examples below + `run.sh` |
| DNS / HTTP / SMTP security analysis | `detect_dns`, `detect_http`, `detect_smtp` |
| Bash automation & alerting | `run.sh` + console alerts in `detect.py` |
| OWASP-based analysis | OWASP A01/A03 mapping in `detect_http` |
| AWS GuardDuty / CloudWatch concepts | `detect_cloud` (**local simulation**, not real AWS) |
| Incident investigation | `investigate.py` |
| Security reporting | `report.py` → `report.txt` |
| TCP/IP knowledge | source IPs / addresses used across every detector |

## 12. Linux command-line investigation examples

```bash
ls -l data/                                  # list the logs
head -n 5 data/auth.log                      # peek at the format
grep "FAILURE" data/auth.log                 # every failed login
grep "FAILURE" data/auth.log | wc -l         # count failures
grep "203.0.113.77" data/auth.log            # everything from the brute-force IP
grep "UNION SELECT" data/http.log            # find the SQL-injection request
grep "../" data/http.log                     # find path-traversal requests
cat report.txt                               # read the final report
```
*(These show Linux/Unix command-line usage — not "daily system administration".)*

## 13. Two-minute interview explanation

> "It's a small threat-intelligence pipeline. I have five kinds of security logs —
> authentication, DNS, HTTP, SMTP, and cloud API events. A Python program parses
> each log and applies one simple detection rule per log type: too many failed
> logins from one IP is an SSH brute-force; too many unique subdomains from one host
> is possible DNS tunneling; SQL-injection or path-traversal strings in a URL are web
> attacks mapped to OWASP; one sender hitting too many recipients is messaging abuse;
> and failed cloud logins or sensitive API actions are GuardDuty-style cloud findings.
> Every detection becomes a 'finding' with a timestamp, source, severity, and evidence,
> and I store them all in a SQLite table. Then I can run SQL queries to see the top
> offenders, investigate a specific IP from the command line to get its evidence and a
> recommended action, and generate a text incident report. A Bash script automates the
> whole thing. It's deliberately simple and honest — pure log analysis, no live capture
> and no real cloud integration."

## 14. Fifteen likely interview questions & answers (based only on this project)

1. **What problem does this solve?** It detects common attack patterns in security logs and turns them into structured, queryable findings with recommended actions.
2. **What are the inputs?** Five small log files: `auth.log`, `dns.log`, `http.log`, `smtp.log`, and `cloud_events.json`.
3. **How does brute-force detection work?** Group `FAILURE` lines by source IP, count them; ≥10 from one IP → `SSH_BRUTE_FORCE`, HIGH.
4. **Why is the DNS rule a good signal?** Malware tunneling data over DNS generates many unique random subdomains of one domain — so ≥15 unique subdomains from one IP is suspicious.
5. **How do you detect web attacks?** Substring match for known SQLi/traversal patterns in the request path, mapped to OWASP A03 (Injection) and A01 (Broken Access Control).
6. **What is the SMTP rule?** Count recipients per sender; >20 → `SMTP_ABUSE` (spam / compromised mailbox).
7. **Is this real AWS GuardDuty?** No. It's a **local simulation** of GuardDuty-style findings over a small JSON sample — no AWS account or API.
8. **Why SQLite instead of PostgreSQL/MySQL?** It's a single file with zero setup, and the data is tiny — perfect for an educational project.
9. **What's in a finding?** `timestamp, threat_type, severity, source, description, evidence` — one consistent shape for all detectors.
10. **How do you investigate an incident?** `python investigate.py <ip>` runs a `WHERE source = ?` query and prints findings, evidence, and the recommended action.
11. **Where do severity levels come from?** Fixed per rule in `detectors.py` (brute-force/web/cloud-tampering = HIGH; DNS/SMTP/failed-login = MEDIUM).
12. **How is the pipeline automated?** `run.sh` checks the input files, runs `detect.py`, then `report.py`, using `set -e` and exit codes.
13. **How would you add a new detector?** Add a `detect_x()` function in `detectors.py` returning the standard dict, then call it in `detect.py`. Nothing else changes.
14. **What are the false-positive risks?** Thresholds are naive — a busy legitimate host could trip DNS/SMTP rules; a real system would tune thresholds and add allow-lists.
15. **What did you intentionally leave out and why?** Real-time streaming, ML, dashboards, real cloud/packet capture — they'd add complexity without changing the core detection concept.

## 15. DO NOT CLAIM (technical honesty)

Do **not** say this project does any of the following — it does not:

- ❌ Real AWS **GuardDuty** or **CloudWatch** integration (it's a **local simulation**)
- ❌ Packet-level **TCP/IP** analysis or **Wireshark**/pcap capture
- ❌ Live **DNS** packet capture
- ❌ A real **SSH** or **SMTP** server (it only reads logs; it sends no email)
- ❌ **Machine learning** / AI-based detection
- ❌ A production **SIEM**, real-time streaming, or event correlation
- ❌ Blocking/firewalling anything (it only *recommends* actions)

What you **can** honestly say: log parsing, rule-based threat detection, OWASP-mapped
web-attack detection, SQLite storage, SQL investigation, Bash automation, and reporting.

## 16. Possible improvements (intentionally NOT implemented)

- Configurable thresholds via a config file / CLI flags
- Allow-lists to cut false positives
- More OWASP categories and regex-based detection
- Time-window logic (e.g. "10 failures within 60 seconds")
- Deduplicating repeated findings per source
- Exporting the report to HTML/PDF
- Reading real syslog / Apache / CloudTrail formats
- Unit tests for each detector
- A tiny read-only web dashboard

These are deliberately left out to keep the project small, honest, and easy to explain.
