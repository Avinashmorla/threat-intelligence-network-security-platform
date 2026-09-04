"""
report.py
---------
Read findings.db and write a simple text security report (report.txt).

Run:  python report.py
"""

import os
import sqlite3

from detectors import RECOMMENDED_ACTION

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "findings.db")
OUT = os.path.join(BASE, "report.txt")


def build_report():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    findings = conn.execute(
        "SELECT * FROM findings ORDER BY severity, threat_type"
    ).fetchall()

    by_severity = conn.execute(
        "SELECT severity, COUNT(*) c FROM findings GROUP BY severity ORDER BY c DESC"
    ).fetchall()
    by_type = conn.execute(
        "SELECT threat_type, COUNT(*) c FROM findings GROUP BY threat_type ORDER BY c DESC"
    ).fetchall()
    top_sources = conn.execute(
        "SELECT source, COUNT(*) c FROM findings GROUP BY source ORDER BY c DESC LIMIT 5"
    ).fetchall()
    conn.close()

    lines = []
    lines.append("=" * 60)
    lines.append("THREAT INTELLIGENCE REPORT")
    lines.append("=" * 60)
    lines.append(f"Total Findings: {len(findings)}")
    lines.append("")

    lines.append("Findings by Severity:")
    for r in by_severity:
        lines.append(f"  {r['severity']:8} {r['c']}")
    lines.append("")

    lines.append("Findings by Threat Type:")
    for r in by_type:
        lines.append(f"  {r['threat_type']:18} {r['c']}")
    lines.append("")

    lines.append("Most Suspicious Sources:")
    for r in top_sources:
        lines.append(f"  {r['source']:18} {r['c']} finding(s)")
    lines.append("")

    lines.append("=" * 60)
    lines.append("INCIDENT DETAILS")
    lines.append("=" * 60)
    for f in findings:
        lines.append(f"[{f['severity']}] {f['threat_type']}")
        lines.append(f"  Source     : {f['source']}")
        lines.append(f"  Time       : {f['timestamp']}")
        lines.append(f"  Description: {f['description']}")
        lines.append(f"  Evidence   : {f['evidence']}")
        lines.append(f"  Action     : {RECOMMENDED_ACTION.get(f['threat_type'], 'Review manually.')}")
        lines.append("")

    return "\n".join(lines)


def main():
    report = build_report()
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(report)
    print(report)
    print(f"\n[+] Report written to {OUT}")


if __name__ == "__main__":
    main()
