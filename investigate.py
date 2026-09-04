"""
investigate.py
--------------
Incident investigation for one source (IP or sender).

    Detection -> Finding -> Evidence -> Investigation -> Recommendation

Run:  python investigate.py 203.0.113.77
"""

import os
import sqlite3
import sys

from detectors import RECOMMENDED_ACTION

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "findings.db")


def investigate(source):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM findings WHERE source = ? ORDER BY timestamp",
        (source,),
    ).fetchall()
    conn.close()

    print("=" * 60)
    print(f"INCIDENT INVESTIGATION FOR SOURCE: {source}")
    print("=" * 60)

    if not rows:
        print("No findings for this source. It looks clean in our data.")
        return

    print(f"{len(rows)} finding(s) associated with this source:\n")
    for r in rows:
        print(f"  Time        : {r['timestamp']}")
        print(f"  Threat type : {r['threat_type']}")
        print(f"  Severity    : {r['severity']}")
        print(f"  Description : {r['description']}")
        print(f"  Evidence    : {r['evidence']}")
        print(f"  Recommended : {RECOMMENDED_ACTION.get(r['threat_type'], 'Review manually.')}")
        print("  " + "-" * 56)


def main():
    if len(sys.argv) < 2:
        print("Usage: python investigate.py <source-ip-or-sender>")
        print("Example: python investigate.py 203.0.113.77")
        sys.exit(1)
    investigate(sys.argv[1])


if __name__ == "__main__":
    main()
