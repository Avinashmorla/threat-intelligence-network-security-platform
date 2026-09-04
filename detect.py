"""
detect.py
---------
The main Python analysis pipeline.

    1. Load each log file and run its detector (detectors.py)
    2. Collect all findings
    3. Store them in a SQLite database (findings.db, table: findings)
    4. Print console alerts (like a lightweight SIEM)

Run:  python detect.py
"""

import os
import sqlite3

from detectors import (
    detect_auth, detect_dns, detect_http, detect_smtp, detect_cloud,
)

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
DB = os.path.join(BASE, "findings.db")


def collect_findings():
    """Run every detector and return one combined list of findings."""
    findings = []
    findings += detect_auth(os.path.join(DATA, "auth.log"))
    findings += detect_dns(os.path.join(DATA, "dns.log"))
    findings += detect_http(os.path.join(DATA, "http.log"))
    findings += detect_smtp(os.path.join(DATA, "smtp.log"))
    findings += detect_cloud(os.path.join(DATA, "cloud_events.json"))
    return findings


def init_db(conn):
    """Create the single findings table if it does not exist."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            threat_type TEXT,
            severity    TEXT,
            source      TEXT,
            description TEXT,
            evidence    TEXT
        )
    """)


def save_findings(conn, findings):
    """Wipe old results and insert the fresh findings (idempotent runs)."""
    conn.execute("DELETE FROM findings")
    conn.executemany(
        """INSERT INTO findings
           (timestamp, threat_type, severity, source, description, evidence)
           VALUES (:timestamp, :threat_type, :severity, :source, :description, :evidence)""",
        findings,
    )
    conn.commit()


def print_alerts(findings):
    """Console output, most severe first."""
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    print(f"\n[+] Detection complete: {len(findings)} finding(s)\n")
    for f in sorted(findings, key=lambda x: order.get(x["severity"], 9)):
        print(f"  [{f['severity']:6}] {f['threat_type']:18} src={f['source']:16} {f['description']}")
    print()


def main():
    findings = collect_findings()
    conn = sqlite3.connect(DB)
    init_db(conn)
    save_findings(conn, findings)
    conn.close()
    print_alerts(findings)
    print(f"[+] {len(findings)} finding(s) saved to {DB}")


if __name__ == "__main__":
    main()
