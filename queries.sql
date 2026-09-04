-- queries.sql
-- Simple SQL investigation queries for the findings table.
-- Run them all with:   sqlite3 findings.db < queries.sql
-- Or open a shell with: sqlite3 findings.db   then paste a query.

-- 1. Show all findings.
SELECT id, timestamp, threat_type, severity, source
FROM findings
ORDER BY timestamp;

-- 2. Show only HIGH severity findings.
SELECT timestamp, threat_type, source, description
FROM findings
WHERE severity = 'HIGH'
ORDER BY timestamp;

-- 3. Count findings by threat type.
SELECT threat_type, COUNT(*) AS total
FROM findings
GROUP BY threat_type
ORDER BY total DESC;

-- 4. Count findings by source.
SELECT source, COUNT(*) AS total
FROM findings
GROUP BY source
ORDER BY total DESC;

-- 5. Identify the most suspicious sources (more than one finding).
SELECT source, COUNT(*) AS total
FROM findings
GROUP BY source
HAVING COUNT(*) >= 1
ORDER BY total DESC
LIMIT 5;
