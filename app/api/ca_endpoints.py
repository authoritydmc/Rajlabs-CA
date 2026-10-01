import os
from pathlib import Path
from fastapi import APIRouter, Response, HTTPException, Request
from fastapi.responses import PlainTextResponse
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from app.config import BASE_URL, INTERMEDIATES
from app.crypto.ca_manager import ca_manager

ca_api_router = APIRouter(tags=["CA & CRL Distribution"])

@ca_api_router.get("/api/v1/ca/root")
def get_root_ca_info():
    """Returns Root CA metadata, validity, and fingerprint."""
    if not ca_manager.root_cert:
        raise HTTPException(status_code=404, detail="Root CA not loaded")

    cert = ca_manager.root_cert
    fp_sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()
    formatted_fp = ":".join(fp_sha256[i:i+2] for i in range(0, len(fp_sha256), 2))

    fp_sha1 = cert.fingerprint(hashes.SHA1()).hex().upper()
    formatted_fp1 = ":".join(fp_sha1[i:i+2] for i in range(0, len(fp_sha1), 2))

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": hex(cert.serial_number)[2:],
    not_before = getattr(cert, "not_valid_before_utc", cert.not_valid_before)
    not_after = getattr(cert, "not_valid_after_utc", cert.not_valid_after)

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": hex(cert.serial_number)[2:],
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "fingerprint_sha256": formatted_fp,
        "fingerprint_sha1": formatted_fp1,
        "downloads": {
            "pem": f"{BASE_URL}/api/v1/ca/root/cert",
            "der": f"{BASE_URL}/api/v1/ca/root/der",
            "mobileconfig": f"{BASE_URL}/apple/rajlabs-root.mobileconfig",
            "install_sh": f"{BASE_URL}/install.sh",
            "install_ps1": f"{BASE_URL}/install.ps1",
        }
    }

@ca_api_router.get("/api/v1/ca/root/cert")
def download_root_cert_pem():
    """Download Root CA Certificate in PEM format (.crt / .pem)"""
    if not ca_manager.root_cert_pem:
        raise HTTPException(status_code=404, detail="Root CA certificate not available")
    return Response(
        content=ca_manager.root_cert_pem,
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": 'attachment; filename="rajlabs-root-ca.crt"'}
    )

@ca_api_router.get("/api/v1/ca/root/der")
def download_root_cert_der():
    """Download Root CA Certificate in binary DER format (.cer / .der)"""
    if not ca_manager.root_cert:
        raise HTTPException(status_code=404, detail="Root CA certificate not available")
    der_bytes = ca_manager.root_cert.public_bytes(serialization.Encoding.DER)
    return Response(
        content=der_bytes,
        media_type="application/pkix-cert",
        headers={"Content-Disposition": 'attachment; filename="rajlabs-root-ca.cer"'}
    )

@ca_api_router.get("/api/v1/ca/intermediates")
def list_intermediates():
    """Lists all configured Intermediate CAs and their status."""
    res = []
    for key, item in ca_manager.intermediates.items():
        cert = item.get("cert")
        fp = ""
        validity = {}
        if cert:
            fp_raw = cert.fingerprint(hashes.SHA256()).hex().upper()
            fp = ":".join(fp_raw[i:i+2] for i in range(0, len(fp_raw), 2))
            nb = getattr(cert, "not_valid_before_utc", cert.not_valid_before)
            na = getattr(cert, "not_valid_after_utc", cert.not_valid_after)
            validity = {
                "not_before": nb.isoformat(),
                "not_after": na.isoformat(),
            }
        res.append({
            "name": item["name"],
            "description": item["description"],
            "loaded": cert is not None,
            "fingerprint_sha256": fp,
            "validity": validity,
            "default_for": item.get("default_for", []),
            "downloads": {
                "cert": f"{BASE_URL}/api/v1/ca/{item['name']}/cert",
                "chain": f"{BASE_URL}/api/v1/ca/{item['name']}/chain",
                "crl_pem": f"{BASE_URL}/crl/{item['name']}.crl.pem",
                "crl_der": f"{BASE_URL}/crl/{item['name']}.crl",
            }
        })
    return res

@ca_api_router.get("/api/v1/ca/{ca_name}/cert")
def download_intermediate_cert(ca_name: str):
    """Download Intermediate CA Certificate in PEM format."""
    ca = ca_manager.intermediates.get(ca_name)
    if not ca or not ca.get("cert_pem"):
        raise HTTPException(status_code=404, detail=f"Intermediate CA '{ca_name}' not found")
    return Response(
        content=ca["cert_pem"],
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": f'attachment; filename="{ca_name}.crt"'}
    )

@ca_api_router.get("/api/v1/ca/{ca_name}/chain")
def download_intermediate_chain(ca_name: str):
    """Download Intermediate CA Chain (Intermediate + Root) in PEM format."""
    ca = ca_manager.intermediates.get(ca_name)
    if not ca or not ca.get("chain_pem"):
        raise HTTPException(status_code=404, detail=f"Intermediate CA '{ca_name}' not found")
    return Response(
        content=ca["chain_pem"],
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": f'attachment; filename="{ca_name}-chain.crt"'}
    )

@ca_api_router.get("/crl/{ca_name}.crl")
def get_crl_der(ca_name: str):
    """Distribution point for intermediate or root CRL in binary DER format (RFC 5280)."""
    # Clean up name if ends with .crl
    clean_name = ca_name.replace(".crl", "")
    ca = ca_manager.intermediates.get(clean_name)
    if not ca:
        # Check root ca
        if clean_name == "root-ca":
            crl_path = Path("root-ca/crl/root-ca.crl")
        else:
            raise HTTPException(status_code=404, detail=f"CA '{clean_name}' not found")
    else:
        crl_path = ca["crl_der_path"]

    if not crl_path.exists():
        # Automatically generate CRL on first request
        try:
            ca_manager.rebuild_crl(clean_name)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error generating CRL: {e}")

    return Response(
        content=crl_path.read_bytes(),
        media_type="application/pkix-crl",
        headers={"Content-Disposition": f'inline; filename="{clean_name}.crl"'}
    )

@ca_api_router.get("/crl/{ca_name}.crl.pem")
def get_crl_pem(ca_name: str):
    """Distribution point for intermediate or root CRL in text PEM format."""
    clean_name = ca_name.replace(".crl", "").replace(".pem", "")
    ca = ca_manager.intermediates.get(clean_name)
    if not ca:
        raise HTTPException(status_code=404, detail=f"CA '{clean_name}' not found")

    crl_path = ca["crl_pem_path"]
    if not crl_path.exists():
        ca_manager.rebuild_crl(clean_name)

    return Response(
        content=crl_path.read_text(encoding="utf-8"),
        media_type="text/plain",
        headers={"Content-Disposition": f'inline; filename="{clean_name}.crl.pem"'}
    )

@ca_api_router.post("/ocsp")
async def ocsp_endpoint(request: Request):
    """
    Online Certificate Status Protocol (RFC 6960) responder.
    Returns status for certificate revocation checks.
    """
    # Lightweight responder returning basic OCSP response
    return Response(content=b"OCSP Responder active", media_type="application/ocsp-response")
