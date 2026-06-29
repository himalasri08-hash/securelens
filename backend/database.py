import sqlite3
import json
import uuid
from datetime import datetime, timezone

DB_PATH = "securelens.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Creates the tables if they don't already exist. Safe to call every startup."""
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            title TEXT,
            language TEXT,
            created_at TEXT,
            total_findings INTEGER,
            highest_severity TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT,
            line INTEGER,
            rule TEXT,
            snippet TEXT,
            severity TEXT,
            explanation TEXT,
            fix_suggestion TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        )
    """)

    conn.commit()
    conn.close()


SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}


def save_scan(title, language, findings):
    """
    Saves a completed scan and all its findings.
    `findings` is a list of dicts, each already containing the LLM's
    severity/explanation/fix_suggestion.
    Returns the new scan_id.
    """
    scan_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    if findings:
        highest = max(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 0))
        highest_severity = highest["severity"]
    else:
        highest_severity = "None"

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO scans (id, title, language, created_at, total_findings, highest_severity) VALUES (?, ?, ?, ?, ?, ?)",
        (scan_id, title, language, created_at, len(findings), highest_severity),
    )

    for f in findings:
        cur.execute(
            """INSERT INTO findings
               (id, scan_id, line, rule, snippet, severity, explanation, fix_suggestion)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(uuid.uuid4()),
                scan_id,
                f.get("line"),
                f.get("rule"),
                f.get("snippet"),
                f.get("severity"),
                f.get("explanation"),
                f.get("fix_suggestion"),
            ),
        )

    conn.commit()
    conn.close()
    return scan_id


def get_dashboard_stats():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) as c FROM scans")
    total_scans = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) as c FROM findings")
    total_findings = cur.fetchone()["c"]

    counts = {}
    for sev in ["Critical", "High", "Medium", "Low"]:
        cur.execute("SELECT COUNT(*) as c FROM findings WHERE severity = ?", (sev,))
        counts[sev.lower()] = cur.fetchone()["c"]

    conn.close()
    return {
        "total_vulnerabilities": total_findings,
        "total_scans": total_scans,
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
    }


def get_history():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans ORDER BY created_at DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_scan_detail(scan_id):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan_row = cur.fetchone()
    if not scan_row:
        conn.close()
        return None

    cur.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
    findings = [dict(r) for r in cur.fetchall()]

    conn.close()
    return {"scan": dict(scan_row), "findings": findings}
