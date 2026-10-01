import json
import base64
import secrets
from typing import Tuple, Dict, Any, Optional
from datetime import datetime, timezone
from app.database.database import get_connection

def b64_decode(data: str) -> bytes:
    """Decodes standard or URL-safe base64 data with padding."""
    rem = len(data) % 4
    if rem > 0:
        data += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data.encode("utf-8"))

def b64_encode(data: bytes) -> str:
    """Encodes bytes into URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def generate_nonce() -> str:
    """Generates a secure random replay-protection nonce and stores it."""
    nonce = secrets.token_urlsafe(24)
    now_str = datetime.now(timezone.utc).isoformat()
    conn = get_connection()
    with conn:
        conn.execute("INSERT INTO acme_nonces (nonce, created_at) VALUES (?, ?)", (nonce, now_str))
    conn.close()
    return nonce

def validate_and_consume_nonce(nonce: str) -> bool:
    """Validates that a nonce exists and immediately deletes it to prevent replay attacks."""
    if not nonce:
        return False
    conn = get_connection()
    with conn:
        cursor = conn.execute("DELETE FROM acme_nonces WHERE nonce = ?", (nonce,))
        valid = cursor.rowcount > 0
    conn.close()
    return valid

def parse_jws(jws_body: Dict[str, Any]) -> Tuple[Dict[str, Any], Any]:
    """
    Extracts protected header and payload from an ACME JWS body.
    """
    protected_b64 = jws_body.get("protected", "")
    payload_b64 = jws_body.get("payload", "")

    try:
        protected_json = b64_decode(protected_b64).decode("utf-8")
        protected_header = json.loads(protected_json)
    except Exception as e:
        raise ValueError(f"Malformed JWS protected header: {e}")

    # Payload can be empty string for POST-as-GET
    payload = None
    if payload_b64:
        try:
            payload_raw = b64_decode(payload_b64).decode("utf-8")
            payload = json.loads(payload_raw)
        except Exception:
            try:
                payload = b64_decode(payload_b64)
            except Exception:
                payload = payload_b64

    return protected_header, payload
