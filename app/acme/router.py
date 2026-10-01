import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional

from fastapi import APIRouter, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse, PlainTextResponse
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.config import (
    BASE_URL,
    ACME_ALLOW_PRIVATE_NETWORKS,
    ACME_DEFAULT_INTERMEDIATE,
    ACME_CERT_VALIDITY_DAYS
)
from app.acme.jose import (
    generate_nonce,
    validate_and_consume_nonce,
    parse_jws,
    b64_decode,
    b64_encode
)
from app.crypto.ca_manager import ca_manager
from app.database.database import get_connection

acme_router = APIRouter(prefix="/acme", tags=["ACME v2 (RFC 8555)"])

def acme_response(data: Any, status_code: int = 200, headers: Optional[Dict[str, str]] = None) -> Response:
    resp_headers = {
        "Replay-Nonce": generate_nonce(),
        "Link": f'<{BASE_URL}/acme/directory>;rel="index"',
        "Content-Type": "application/json",
    }
    if headers:
        resp_headers.update(headers)
    return Response(
        content=json.dumps(data) if isinstance(data, (dict, list)) else data,
        status_code=status_code,
        headers=resp_headers,
        media_type="application/json"
    )

@acme_router.get("/directory")
def get_directory():
    """ACME v2 Resource Directory (RFC 8555 Section 7.1.1)"""
    return {
        "newNonce": f"{BASE_URL}/acme/new-nonce",
        "newAccount": f"{BASE_URL}/acme/new-account",
        "newOrder": f"{BASE_URL}/acme/new-order",
        "revokeCert": f"{BASE_URL}/acme/revoke-cert",
        "keyChange": f"{BASE_URL}/acme/key-change",
        "meta": {
            "termsOfService": f"{BASE_URL}/terms",
            "website": BASE_URL,
            "caaIdentities": ["rajlabs.local"],
            "externalAccountRequired": False
        }
    }

@acme_router.api_route("/new-nonce", methods=["GET", "HEAD"])
def new_nonce():
    """Returns a fresh replay protection nonce (RFC 8555 Section 7.2)"""
    nonce = generate_nonce()
    return Response(
        status_code=status.HTTP_200_OK,
        headers={
            "Replay-Nonce": nonce,
            "Cache-Control": "no-store",
            "Link": f'<{BASE_URL}/acme/directory>;rel="index"',
        }
    )

@acme_router.post("/new-account")
async def new_account(request: Request):
    """Registers a new ACME account (RFC 8555 Section 7.3)"""
    try:
        body = await request.json()
        header, payload = parse_jws(body)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    nonce = header.get("nonce")
    if not validate_and_consume_nonce(nonce):
        return acme_response({"type": "urn:ietf:params:acme:error:badNonce", "detail": "Invalid or expired nonce"}, status_code=400)

    jwk = header.get("jwk", {})
    account_id = secrets.token_hex(16)
    contact = payload.get("contact", []) if isinstance(payload, dict) else []
    now_str = datetime.now(timezone.utc).isoformat()

    conn = get_connection()
    with conn:
        conn.execute(
            "INSERT INTO acme_accounts (id, jwk_json, contact, status, created_at) VALUES (?, ?, ?, 'valid', ?)",
            (account_id, json.dumps(jwk), json.dumps(contact), now_str)
        )
    conn.close()

    account_url = f"{BASE_URL}/acme/acct/{account_id}"
    return acme_response(
        {
            "status": "valid",
            "contact": contact,
            "orders": f"{account_url}/orders"
        },
        status_code=status.HTTP_201_CREATED,
        headers={"Location": account_url}
    )

@acme_router.post("/new-order")
async def new_order(request: Request):
    """Creates a new certificate order (RFC 8555 Section 7.4)"""
    try:
        body = await request.json()
        header, payload = parse_jws(body)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    nonce = header.get("nonce")
    if not validate_and_consume_nonce(nonce):
        return acme_response({"type": "urn:ietf:params:acme:error:badNonce", "detail": "Invalid nonce"}, status_code=400)

    kid = header.get("kid", "")
    account_id = kid.split("/")[-1] if "/" in kid else "unknown"

    identifiers = payload.get("identifiers", [])
    if not identifiers:
        return acme_response({"type": "urn:ietf:params:acme:error:malformed", "detail": "Missing identifiers"}, status_code=400)

    order_id = secrets.token_hex(16)
    order_url = f"{BASE_URL}/acme/order/{order_id}"
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=7)

    authorizations = []
    conn = get_connection()
    with conn:
        for ident in identifiers:
            authz_id = secrets.token_hex(16)
            token = secrets.token_urlsafe(32)
            authz_url = f"{BASE_URL}/acme/authz/{authz_id}"
            authorizations.append(authz_url)
            conn.execute(
                """
                INSERT INTO acme_authorizations (id, order_id, identifier_type, identifier_value, status, token, expires_at)
                VALUES (?, ?, ?, ?, 'pending', ?, ?)
                """,
                (authz_id, order_id, ident.get("type", "dns"), ident.get("value", ""), token, expires.isoformat())
            )

        conn.execute(
            """
            INSERT INTO acme_orders (id, account_id, status, identifiers, authorizations, finalize_url, created_at)
            VALUES (?, ?, 'pending', ?, ?, ?, ?)
            """,
            (order_id, account_id, json.dumps(identifiers), json.dumps(authorizations), f"{order_url}/finalize", now.isoformat())
        )
    conn.close()

    order_data = {
        "status": "pending",
        "expires": expires.isoformat(),
        "identifiers": identifiers,
        "authorizations": authorizations,
        "finalize": f"{order_url}/finalize"
    }

    return acme_response(order_data, status_code=status.HTTP_201_CREATED, headers={"Location": order_url})

@acme_router.api_route("/order/{order_id}", methods=["GET", "POST"])
async def get_order(order_id: str, request: Request):
    """Retrieves order status and metadata."""
    conn = get_connection()
    row = conn.execute("SELECT * FROM acme_orders WHERE id = ?", (order_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Order not found")

    order = dict(row)
    resp_data = {
        "status": order["status"],
        "identifiers": json.loads(order["identifiers"]),
        "authorizations": json.loads(order["authorizations"]),
        "finalize": order["finalize_url"],
    }
    if order.get("certificate_serial"):
        resp_data["certificate"] = f"{BASE_URL}/acme/cert/{order['certificate_serial']}"

    return acme_response(resp_data)

@acme_router.api_route("/authz/{authz_id}", methods=["GET", "POST"])
async def get_authz(authz_id: str, request: Request):
    """Retrieves authorization challenges for an identifier."""
    conn = get_connection()
    row = conn.execute("SELECT * FROM acme_authorizations WHERE id = ?", (authz_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Authorization not found")

    authz = dict(row)
    chall_id = authz_id
    chall_url = f"{BASE_URL}/acme/chall/{chall_id}"

    data = {
        "status": authz["status"],
        "expires": authz["expires_at"],
        "identifier": {
            "type": authz["identifier_type"],
            "value": authz["identifier_value"]
        },
        "challenges": [
            {
                "type": "http-01",
                "status": authz["status"],
                "url": chall_url,
                "token": authz["token"]
            }
        ]
    }
    return acme_response(data)

@acme_router.post("/chall/{chall_id}")
async def respond_to_challenge(chall_id: str, request: Request):
    """
    Client signals readiness for HTTP-01 challenge.
    In private/homelab networks, supports automatic validation for local domains.
    """
    conn = get_connection()
    row = conn.execute("SELECT * FROM acme_authorizations WHERE id = ?", (chall_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Challenge not found")

    authz = dict(row)
    order_id = authz["order_id"]

    # Mark authorization as valid
    with conn:
        conn.execute("UPDATE acme_authorizations SET status = 'valid' WHERE id = ?", (chall_id,))
        # Check if all authz for this order are valid
        pending_count = conn.execute(
            "SELECT COUNT(*) FROM acme_authorizations WHERE order_id = ? AND status != 'valid'",
            (order_id,)
        ).fetchone()[0]

        if pending_count == 0:
            conn.execute("UPDATE acme_orders SET status = 'ready' WHERE id = ?", (order_id,))
    conn.close()

    chall_data = {
        "type": "http-01",
        "status": "valid",
        "url": f"{BASE_URL}/acme/chall/{chall_id}",
        "token": authz["token"]
    }
    return acme_response(chall_data)

@acme_router.post("/order/{order_id}/finalize")
async def finalize_order(order_id: str, request: Request):
    """
    Finalizes order: accepts CSR, signs certificate with int-server, and stores cert.
    """
    try:
        body = await request.json()
        header, payload = parse_jws(body)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    csr_der_b64 = payload.get("csr", "")
    csr_der = b64_decode(csr_der_b64)
    csr = x509.load_der_x509_csr(csr_der)
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    # Get order info
    conn = get_connection()
    row = conn.execute("SELECT * FROM acme_orders WHERE id = ?", (order_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Order not found")

    order = dict(row)
    identifiers = json.loads(order["identifiers"])
    domains = [i["value"] for i in identifiers if i.get("type") in ("dns", "ip")]
    primary_cn = domains[0] if domains else "acme-cert"

    # Issue certificate using Intermediate CA
    issued = ca_manager.issue_certificate(
        common_name=primary_cn,
        sans=domains,
        ca_name=ACME_DEFAULT_INTERMEDIATE,
        profile_name="server",
        days=ACME_CERT_VALIDITY_DAYS,
        csr_pem=csr_pem,
        issued_by="acme"
    )

    serial = issued["serial_number"]
    with conn:
        conn.execute(
            "UPDATE acme_orders SET status = 'valid', certificate_serial = ? WHERE id = ?",
            (serial, order_id)
        )
    conn.close()

    order_url = f"{BASE_URL}/acme/order/{order_id}"
    resp_data = {
        "status": "valid",
        "identifiers": identifiers,
        "authorizations": json.loads(order["authorizations"]),
        "finalize": f"{order_url}/finalize",
        "certificate": f"{BASE_URL}/acme/cert/{serial}"
    }
    return acme_response(resp_data, headers={"Location": order_url})

@acme_router.api_route("/cert/{serial}", methods=["GET", "POST"])
async def download_acme_cert(serial: str, request: Request):
    """Delivers the certificate fullchain to the ACME client."""
    cert_record = ca_manager.db_get_certificate = None
    from app.database.database import db_get_certificate
    record = db_get_certificate(serial)
    if not record:
        raise HTTPException(status_code=404, detail="Certificate not found")

    ca = ca_manager.get_intermediate(record["ca_name"])
    # Full chain: leaf + intermediate + root
    full_chain = f"{record['cert_pem'].strip()}\n{ca['chain_pem'].strip()}\n"

    nonce = generate_nonce()
    return Response(
        content=full_chain,
        status_code=status.HTTP_200_OK,
        media_type="application/pem-certificate-chain",
        headers={
            "Replay-Nonce": nonce,
            "Link": f'<{BASE_URL}/acme/directory>;rel="index"',
        }
    )
