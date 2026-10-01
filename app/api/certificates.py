from typing import List, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Query, Response, Depends, Header
from fastapi.responses import PlainTextResponse

from app.config import API_KEY, BASE_URL
from app.crypto.ca_manager import ca_manager
from app.database.database import (
    db_list_certificates,
    db_get_certificate,
    db_get_stats
)

cert_router = APIRouter(prefix="/api/v1", tags=["Certificates CRUD"])

def verify_api_key(x_api_key: Optional[str] = Header(None)):
    """Verifies API key if provided. Defaults to open/local if API_KEY unset."""
    if API_KEY and API_KEY != "rajlabs_super_secret_api_key_change_me_in_production":
        if x_api_key != API_KEY:
            raise HTTPException(status_code=401, detail="Invalid API Key")
    return True

class IssueCertRequest(BaseModel):
    common_name: str = Field(..., example="grafana.rajlabs.local")
    sans: List[str] = Field(default_factory=list, example=["grafana.rajlabs.local", "192.168.1.50"])
    ca_name: str = Field("int-server", example="int-server")
    profile: str = Field("server", example="server")
    key_algorithm: str = Field("rsa2048", example="rsa2048")
    days: Optional[int] = Field(None, example=365)
    csr_pem: Optional[str] = Field(None, description="Optional CSR for zero-trust client signing")

class RevokeCertRequest(BaseModel):
    reason: str = Field("unspecified", example="keyCompromise")

class PFXExportRequest(BaseModel):
    password: str = Field(..., min_length=1, example="MyExportPassword123")

@cert_router.get("/stats")
def get_pki_stats():
    """Returns total, active, expiring, and revoked certificate metrics."""
    return db_get_stats()

@cert_router.get("/certificates")
def list_certificates(
    ca_name: Optional[str] = Query(None, description="Filter by intermediate CA"),
    status: Optional[str] = Query(None, description="Filter by status: VALID, REVOKED, EXPIRED"),
    search: Optional[str] = Query(None, description="Search by CN, SAN, or Serial")
):
    """Lists certificates matching query filters."""
    certs = db_list_certificates(ca_name=ca_name, status=status, query=search)
    return certs

@cert_router.post("/certificates")
def issue_certificate(req: IssueCertRequest):
    """Issues a new certificate signed by the selected intermediate CA."""
    try:
        issued = ca_manager.issue_certificate(
            common_name=req.common_name,
            sans=req.sans,
            ca_name=req.ca_name,
            profile_name=req.profile,
            key_algorithm=req.key_algorithm,
            days=req.days,
            csr_pem=req.csr_pem,
            issued_by="api"
        )
        return issued
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@cert_router.get("/certificates/{serial}")
def get_certificate_details(serial: str):
    """Retrieves full details, PEM certificate, and CA chain for a certificate."""
    cert = db_get_certificate(serial)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")

    ca = ca_manager.intermediates.get(cert["ca_name"], {})
    chain_pem = f"{cert['cert_pem'].strip()}\n{ca.get('chain_pem', '').strip()}\n"

    cert["chain_pem"] = chain_pem
    cert["has_private_key"] = bool(cert.get("priv_key_pem"))
    return cert

@cert_router.get("/certificates/{serial}/cert")
def download_cert_pem(serial: str):
    """Download Certificate in PEM format."""
    cert = db_get_certificate(serial)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return Response(
        content=cert["cert_pem"],
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": f'attachment; filename="{cert["common_name"]}.crt"'}
    )

@cert_router.get("/certificates/{serial}/key")
def download_key_pem(serial: str):
    """Download Private Key in PEM format (if generated on server)."""
    cert = db_get_certificate(serial)
    if not cert or not cert.get("priv_key_pem"):
        raise HTTPException(status_code=404, detail="Private key not available for this certificate (e.g. CSR used)")
    return Response(
        content=cert["priv_key_pem"],
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{cert["common_name"]}.key"'}
    )

@cert_router.get("/certificates/{serial}/chain")
def download_cert_chain(serial: str):
    """Download Full Chain (Leaf + Intermediate + Root CA) in PEM format."""
    cert = db_get_certificate(serial)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    ca = ca_manager.intermediates.get(cert["ca_name"], {})
    full_chain = f"{cert['cert_pem'].strip()}\n{ca.get('chain_pem', '').strip()}\n"
    return Response(
        content=full_chain,
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": f'attachment; filename="{cert["common_name"]}-fullchain.crt"'}
    )

@cert_router.post("/certificates/{serial}/pfx")
def export_pfx(serial: str, req: PFXExportRequest):
    """Packages the certificate, private key, and chain into a PKCS#12 (.pfx/.p12) bundle with password."""
    cert = db_get_certificate(serial)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    if not cert.get("priv_key_pem"):
        raise HTTPException(status_code=400, detail="Cannot export PFX: Private key was not stored on server (CSR signing)")

    try:
        pfx_bytes = ca_manager.export_pkcs12(
            cert_pem=cert["cert_pem"],
            key_pem=cert["priv_key_pem"],
            password=req.password,
            name=cert["common_name"]
        )
        return Response(
            content=pfx_bytes,
            media_type="application/x-pkcs12",
            headers={"Content-Disposition": f'attachment; filename="{cert["common_name"]}.pfx"'}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PFX export error: {e}")

@cert_router.post("/certificates/{serial}/renew")
def renew_certificate(serial: str, days: Optional[int] = Query(None)):
    """Renews an existing certificate with a new expiration date."""
    try:
        renewed = ca_manager.renew_certificate(serial, new_days=days)
        return renewed
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@cert_router.post("/certificates/{serial}/revoke")
def revoke_certificate(serial: str, req: RevokeCertRequest):
    """Revokes a certificate with an RFC 5280 reason code and rebuilds the CRL."""
    try:
        success = ca_manager.revoke_certificate(serial, reason=req.reason, actor="api")
        if not success:
            raise HTTPException(status_code=400, detail="Failed to revoke certificate (may already be revoked)")
        return {"status": "success", "message": f"Certificate {serial} revoked. CRL updated successfully."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@cert_router.get("/certificates/{serial}/config")
def get_server_configs(serial: str):
    """Generates ready-to-paste server configurations for Nginx, Caddy, Traefik, and Apache."""
    cert = db_get_certificate(serial)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")

    cn = cert["common_name"]
    nginx = f"""server {{
    listen 443 ssl http2;
    server_name {cn};

    ssl_certificate /etc/ssl/certs/{cn}-fullchain.crt;
    ssl_certificate_key /etc/ssl/private/{cn}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {{
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }}
}}"""

    caddy = f"""{cn} {{
    tls /etc/ssl/certs/{cn}-fullchain.crt /etc/ssl/private/{cn}.key
    reverse_proxy localhost:3000
}}"""

    traefik = f"""tls:
  certificates:
    - certFile: /etc/ssl/certs/{cn}-fullchain.crt
      keyFile: /etc/ssl/private/{cn}.key"""

    apache = f"""<VirtualHost *:443>
    ServerName {cn}
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/{cn}.crt
    SSLCertificateKeyFile /etc/ssl/private/{cn}.key
    SSLCertificateChainFile /etc/ssl/certs/ca-chain.crt
</VirtualHost>"""

    return {
        "common_name": cn,
        "nginx": nginx,
        "caddy": caddy,
        "traefik": traefik,
        "apache": apache,
    }
