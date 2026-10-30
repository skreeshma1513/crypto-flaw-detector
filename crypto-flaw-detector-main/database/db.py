"""SQLite helper functions. Tables are created automatically by init_db()."""
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    scan_date TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    ai_prediction TEXT NOT NULL,
    ai_confidence REAL NOT NULL,
    finding_count INTEGER NOT NULL,
    static_score INTEGER DEFAULT 0,
    explanation TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id TEXT, title TEXT, severity TEXT, line_number INTEGER,
    description TEXT, evidence TEXT, recommendation TEXT
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'Security Analyst',
    created_at TEXT NOT NULL
);
"""


def _connect():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with _connect() as conn:
        conn.executescript(SCHEMA)
        existing = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if existing == 0:
            default_hash = generate_password_hash("admin123")
            conn.execute(
                "INSERT INTO users (username, password_hash, email, role, created_at) VALUES (?, ?, ?, ?, ?)",
                ("admin", default_hash, "admin@cryptoguard.ai", "Lead Cryptographer",
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )


def get_user_by_username(username):
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id):
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def create_user(username, password, email="", role="Security Analyst"):
    with _connect() as conn:
        p_hash = generate_password_hash(password)
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, email, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (username.strip(), p_hash, email.strip(), role, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        return cur.lastrowid


def verify_user(username, password):
    user = get_user_by_username(username.strip())
    if user and check_password_hash(user["password_hash"], password):
        return user
    return None


def save_scan(filename, risk, ai, findings):
    """Insert one scan and all its findings in a single transaction."""
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans (filename, scan_date, risk_score, risk_level, ai_prediction, ai_confidence,"
            " finding_count, static_score, explanation) VALUES (?,?,?,?,?,?,?,?,?)",
            (filename, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), risk["risk_score"], risk["risk_level"],
             ai["prediction"], ai["confidence"], len(findings), risk["static_score"], risk["explanation"]))
        scan_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO findings (scan_id, rule_id, title, severity, line_number, description, evidence,"
            " recommendation) VALUES (?,?,?,?,?,?,?,?)",
            [(scan_id, f["rule_id"], f["title"], f["severity"], f["line"], f["description"], f["evidence"],
              f["recommendation"]) for f in findings])
    return scan_id


def get_scan(scan_id):
    with _connect() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if scan is None:
            return None, []
        rows = conn.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY line_number", (scan_id,)).fetchall()
    return dict(scan), [dict(r) for r in rows]


def list_scans(limit=None):
    sql = "SELECT * FROM scans ORDER BY id DESC" + (f" LIMIT {int(limit)}" if limit else "")
    with _connect() as conn:
        return [dict(r) for r in conn.execute(sql).fetchall()]


def get_stats():
    with _connect() as conn:
        total, avg = conn.execute("SELECT COUNT(*), AVG(risk_score) FROM scans").fetchone()
        sev = {r["severity"]: r["n"] for r in conn.execute(
            "SELECT severity, COUNT(*) n FROM findings GROUP BY severity")}
        trend = [dict(r) for r in conn.execute(
            "SELECT id, filename, risk_score FROM scans ORDER BY id DESC LIMIT 10")][::-1]
    counts = {k: sev.get(k, 0) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    return {"total_scans": total, "avg_risk": round(avg or 0, 1), "severity": counts,
            "high_critical": counts["CRITICAL"] + counts["HIGH"], "medium": counts["MEDIUM"],
            "low": counts["LOW"], "trend": trend}
