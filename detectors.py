"""
detectors.py
------------
Parsing + threat-detection RULES for each log type.

Every detector returns a list of "finding" dicts that all share the SAME shape:

    {
        "timestamp":   "2026-08-17T08:01:43",
        "threat_type": "SSH_BRUTE_FORCE",
        "severity":    "HIGH",
        "source":      "203.0.113.77",
        "description": "human-readable summary",
        "evidence":    "the raw facts that triggered the rule"
    }

This is LOG ANALYSIS ONLY. No packet capture, no live network sniffing,
no real SSH/SMTP servers, no real cloud APIs.
"""

import json
from collections import defaultdict

# ----------------------------------------------------------------------
# Detection thresholds — deliberately simple so they are easy to explain.
# ----------------------------------------------------------------------
BRUTE_FORCE_THRESHOLD = 10          # failed logins from one IP
DNS_UNIQUE_SUBDOMAIN_THRESHOLD = 15 # unique subdomains of one domain from one IP
SMTP_RECIPIENT_THRESHOLD = 20       # recipients from one sender

# Attack strings we look for in HTTP requests (lower-cased match).
SQLI_PATTERNS = ["' or 1=1", "union select", "or '1'='1", "'--", "; drop table"]
TRAVERSAL_PATTERNS = ["../", "..\\", "/etc/passwd", "win.ini"]

# Sensitive cloud API actions (GuardDuty-style "someone is tampering" signals).
SENSITIVE_CLOUD_ACTIONS = {
    "CreateAccessKey", "PutUserPolicy", "DeleteTrail",
    "StopLogging", "AuthorizeSecurityGroupIngress",
}

# Recommended action per threat type — used by the report and the investigator.
RECOMMENDED_ACTION = {
    "SSH_BRUTE_FORCE":   "Block the source IP at the firewall and reset any targeted accounts.",
    "DNS_ANOMALY":       "Inspect the host for DNS tunneling/malware and sinkhole the domain.",
    "WEB_INJECTION":     "Block the source IP, review WAF rules, and patch the vulnerable endpoint.",
    "SMTP_ABUSE":        "Throttle or suspend the sender and check for a compromised mailbox.",
    "CLOUD_API_ANOMALY": "Rotate credentials, review CloudTrail, and tighten the IAM permissions.",
}


# ----------------------------------------------------------------------
# Small helper: read a pipe-delimited log file into rows of columns.
# ----------------------------------------------------------------------
def load_pipe(path):
    """Return a list of column-lists. Skips blank lines and '#' comments."""
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rows.append([col.strip() for col in line.split("|")])
    return rows


# ----------------------------------------------------------------------
# 1. AUTHENTICATION  ->  SSH_BRUTE_FORCE
#    Rule: one source IP with >= BRUTE_FORCE_THRESHOLD failed logins.
# ----------------------------------------------------------------------
def detect_auth(path):
    findings = []
    fails = defaultdict(list)  # ip -> list of (timestamp, user)
    for ts, status, user, ip in load_pipe(path):
        if status == "FAILURE":
            fails[ip].append((ts, user))

    for ip, attempts in fails.items():
        if len(attempts) >= BRUTE_FORCE_THRESHOLD:
            users = sorted({u for _, u in attempts})
            findings.append({
                "timestamp": attempts[-1][0],
                "threat_type": "SSH_BRUTE_FORCE",
                "severity": "HIGH",
                "source": ip,
                "description": f"{len(attempts)} failed logins from {ip} (brute-force pattern).",
                "evidence": f"attempts={len(attempts)}; targeted_users={', '.join(users)}",
            })
    return findings


# ----------------------------------------------------------------------
# 2. DNS  ->  DNS_ANOMALY
#    Rule: one source IP asking for many UNIQUE subdomains of one domain
#          (classic DNS tunneling / data-exfil signature).
# ----------------------------------------------------------------------
def detect_dns(path):
    findings = []
    queries = defaultdict(set)   # (ip, base_domain) -> set of full query names
    last_ts = {}                 # (ip, base_domain) -> last seen timestamp
    for ts, ip, query, _qtype in load_pipe(path):
        base = ".".join(query.split(".")[-2:])   # e.g. evil-domain.com
        queries[(ip, base)].add(query)
        last_ts[(ip, base)] = ts

    for (ip, base), names in queries.items():
        if len(names) >= DNS_UNIQUE_SUBDOMAIN_THRESHOLD:
            sample = sorted(names)[:3]
            findings.append({
                "timestamp": last_ts[(ip, base)],
                "threat_type": "DNS_ANOMALY",
                "severity": "MEDIUM",
                "source": ip,
                "description": f"{len(names)} unique subdomains of {base} from {ip} (possible DNS tunneling).",
                "evidence": f"domain={base}; unique_queries={len(names)}; sample={sample}",
            })
    return findings


# ----------------------------------------------------------------------
# 3. HTTP  ->  WEB_INJECTION
#    Rule: request path contains a known SQLi or path-traversal pattern.
#    Mapped to the relevant OWASP Top 10 category.
# ----------------------------------------------------------------------
def detect_http(path):
    findings = []
    for ts, ip, method, url, status in load_pipe(path):
        low = url.lower()
        hit = owasp = None
        if any(p in low for p in SQLI_PATTERNS):
            hit, owasp = "SQL injection", "OWASP A03:2021 Injection"
        elif any(p in low for p in TRAVERSAL_PATTERNS):
            hit, owasp = "Path traversal", "OWASP A01:2021 Broken Access Control"

        if hit:
            findings.append({
                "timestamp": ts,
                "threat_type": "WEB_INJECTION",
                "severity": "HIGH",
                "source": ip,
                "description": f"{hit} attempt in HTTP request ({owasp}).",
                "evidence": f"{method} {url} -> {status}",
            })
    return findings


# ----------------------------------------------------------------------
# 4. SMTP  ->  SMTP_ABUSE
#    Rule: one sender delivering to > SMTP_RECIPIENT_THRESHOLD recipients.
# ----------------------------------------------------------------------
def detect_smtp(path):
    findings = []
    rcpts = defaultdict(list)  # sender -> list of recipients
    sender_ip = {}
    sender_ts = {}
    for ts, sender, ip, rcpt in load_pipe(path):
        rcpts[sender].append(rcpt)
        sender_ip[sender] = ip
        sender_ts[sender] = ts

    for sender, recipients in rcpts.items():
        if len(recipients) > SMTP_RECIPIENT_THRESHOLD:
            findings.append({
                "timestamp": sender_ts[sender],
                "threat_type": "SMTP_ABUSE",
                "severity": "MEDIUM",
                "source": sender_ip[sender],
                "description": f"{sender} sent to {len(recipients)} recipients (spam/messaging abuse).",
                "evidence": f"sender={sender}; recipients={len(recipients)}; sample={recipients[:3]}",
            })
    return findings


# ----------------------------------------------------------------------
# 5. CLOUD / API  ->  CLOUD_API_ANOMALY
#    LOCAL SIMULATION of GuardDuty-style findings (no real AWS involved).
#    Rule: failed console logins, or use of a sensitive API action.
# ----------------------------------------------------------------------
def detect_cloud(path):
    findings = []
    with open(path, encoding="utf-8") as f:
        events = json.load(f)

    for e in events:
        reason = None
        severity = "MEDIUM"
        if e.get("event") == "ConsoleLogin" and e.get("result") == "Failed":
            reason = "Failed console login (possible credential attack)"
        elif e.get("event") in SENSITIVE_CLOUD_ACTIONS:
            reason = f"Sensitive API action '{e.get('event')}'"
            severity = "HIGH"

        if reason:
            findings.append({
                "timestamp": e.get("timestamp"),
                "threat_type": "CLOUD_API_ANOMALY",
                "severity": severity,
                "source": e.get("src"),
                "description": f"{reason} by user={e.get('user')}.",
                "evidence": f"event={e.get('event')}; result={e.get('result')}; note={e.get('note')}",
            })
    return findings
