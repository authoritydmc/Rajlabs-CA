import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from app.config import DB_PATH

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serial_number TEXT UNIQUE NOT NULL,
                common_name TEXT NOT NULL,
                sans TEXT DEFAULT '[]',
                ca_name TEXT NOT NULL,
                profile TEXT NOT NULL,
                key_algorithm TEXT NOT NULL,
                not_before TEXT NOT NULL,
                not_after TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'VALID',
                revocation_date TEXT,
                revocation_reason TEXT,
                cert_pem TEXT NOT NULL,
                priv_key_pem TEXT,
                csr_pem TEXT,
                fingerprint_sha256 TEXT,
                created_at TEXT NOT NULL,
                issued_by TEXT DEFAULT 'manual'
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cert_serial ON certificates(serial_number);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cert_ca ON certificates(ca_name);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cert_status ON certificates(status);")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS acme_accounts (
                id TEXT PRIMARY KEY,
                jwk_json TEXT NOT NULL,
                contact TEXT DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'valid',
                created_at TEXT NOT NULL
            );
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS acme_orders (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                identifiers TEXT NOT NULL,
                authorizations TEXT NOT NULL,
                finalize_url TEXT NOT NULL,
                certificate_serial TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (account_id) REFERENCES acme_accounts(id)
            );
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS acme_authorizations (
                id TEXT PRIMARY KEY,
                order_id TEXT NOT NULL,
                identifier_type TEXT NOT NULL,
                identifier_value TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                token TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (order_id) REFERENCES acme_orders(id)
            );
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS acme_nonces (
                nonce TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            );
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                actor TEXT,
                details TEXT
            );
        """)
    conn.close()

# Certificate DB Operations
def db_save_certificate(
    serial_number: str,
    common_name: str,
    sans: List[str],
    ca_name: str,
    profile: str,
    key_algorithm: str,
    not_before: datetime,
    not_after: datetime,
    cert_pem: str,
    priv_key_pem: Optional[str] = None,
    csr_pem: Optional[str] = None,
    fingerprint_sha256: Optional[str] = None,
    issued_by: str = "manual"
) -> int:
    conn = get_connection()
    now_str = datetime.now(timezone.utc).isoformat()
    with conn:
        cursor = conn.execute(
            """
            INSERT INTO certificates (
                serial_number, common_name, sans, ca_name, profile,
                key_algorithm, not_before, not_after, status, cert_pem,
                priv_key_pem, csr_pem, fingerprint_sha256, created_at, issued_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'VALID', ?, ?, ?, ?, ?, ?)
            """,
            (
                serial_number,
                common_name,
                json.dumps(sans),
                ca_name,
                profile,
                key_algorithm,
                not_before.isoformat(),
                not_after.isoformat(),
                cert_pem,
                priv_key_pem,
                csr_pem,
                fingerprint_sha256,
                now_str,
                issued_by
            )
        )
        cert_id = cursor.lastrowid
        # Log audit
        conn.execute(
            "INSERT INTO audit_logs (timestamp, action, target, actor, details) VALUES (?, ?, ?, ?, ?)",
            (now_str, "ISSUE", f"Cert {serial_number} ({common_name})", issued_by, f"Issued by {ca_name}")
        )
    conn.close()
    return cert_id

def db_list_certificates(ca_name: Optional[str] = None, status: Optional[str] = None, query: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_connection()
    sql = "SELECT * FROM certificates WHERE 1=1"
    params = []
    if ca_name:
        sql += " AND ca_name = ?"
        params.append(ca_name)
    if status:
        sql += " AND status = ?"
        params.append(status)
    if query:
        sql += " AND (common_name LIKE ? OR serial_number LIKE ? OR sans LIKE ?)"
        like_query = f"%{query}%"
        params.extend([like_query, like_query, like_query])
    sql += " ORDER BY id DESC"
    
    rows = conn.execute(sql, params).fetchall()
    results = []
    now = datetime.now(timezone.utc)
    with conn:
        for r in rows:
            d = dict(r)
            d["sans"] = json.loads(d["sans"]) if d["sans"] else []
            # Check if expired
            try:
                not_after = datetime.fromisoformat(d["not_after"])
                if d["status"] == "VALID" and not_after < now:
                    d["status"] = "EXPIRED"
                    conn.execute("UPDATE certificates SET status = 'EXPIRED' WHERE id = ?", (d["id"],))
            except Exception:
                pass
            results.append(d)
    conn.close()
    return results

def db_get_certificate(serial_or_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM certificates WHERE serial_number = ? OR id = ?",
        (serial_or_id, serial_or_id)
    ).fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["sans"] = json.loads(d["sans"]) if d["sans"] else []
    return d

def db_revoke_certificate(serial_number: str, reason: str = "unspecified", actor: str = "admin") -> bool:
    conn = get_connection()
    now_str = datetime.now(timezone.utc).isoformat()
    success = False
    with conn:
        cursor = conn.execute(
            """
            UPDATE certificates 
            SET status = 'REVOKED', revocation_date = ?, revocation_reason = ? 
            WHERE serial_number = ? AND status = 'VALID'
            """,
            (now_str, reason, serial_number)
        )
        if cursor.rowcount > 0:
            conn.execute(
                "INSERT INTO audit_logs (timestamp, action, target, actor, details) VALUES (?, ?, ?, ?, ?)",
                (now_str, "REVOKE", f"Cert {serial_number}", actor, f"Reason: {reason}")
            )
            success = True
    conn.close()
    return success

def db_get_revoked_certificates(ca_name: str) -> List[Dict[str, Any]]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT serial_number, revocation_date, revocation_reason FROM certificates WHERE ca_name = ? AND status = 'REVOKED'",
        (ca_name,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def db_get_stats() -> Dict[str, Any]:
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]
    active = conn.execute("SELECT COUNT(*) FROM certificates WHERE status = 'VALID'").fetchone()[0]
    revoked = conn.execute("SELECT COUNT(*) FROM certificates WHERE status = 'REVOKED'").fetchone()[0]
    expired = conn.execute("SELECT COUNT(*) FROM certificates WHERE status = 'EXPIRED'").fetchone()[0]
    conn.close()
    return {
        "total": total,
        "active": active,
        "revoked": revoked,
        "expired": expired
    }
