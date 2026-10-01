import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Network & Host
PORT = int(os.getenv("PORT", "8000"))
HOST = os.getenv("HOST", "0.0.0.0")
BASE_URL = os.getenv("BASE_URL", "https://backend.rajlabs.in/cert-signer").rstrip("/")

# Authentication
API_KEY = os.getenv("API_KEY", "rajlabs_super_secret_api_key_change_me_in_production")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "rajlabs123")

# CA Directory Paths
ROOT_CA_DIR = BASE_DIR / "root-ca"
ROOT_CERT_PATH = ROOT_CA_DIR / "certs" / "root-ca.cert.pem"
ROOT_KEY_PATH = ROOT_CA_DIR / "private" / "root-ca.key.pem"

INTERMEDIATES = {
    "int-server": {
        "name": "int-server",
        "description": "Server & TLS Infrastructure CA",
        "dir": BASE_DIR / "int-server",
        "cert": BASE_DIR / "int-server" / "certs" / "int-server.cert.pem",
        "key": BASE_DIR / "int-server" / "private" / "int-server.key.pem",
        "chain": BASE_DIR / "int-server" / "certs" / "ca-chain.cert.pem",
        "crl": BASE_DIR / "int-server" / "crl" / "int-server.crl.pem",
        "crl_der": BASE_DIR / "int-server" / "crl" / "int-server.crl",
        "default_for": ["web", "server", "acme"],
    },
    "int-wifi": {
        "name": "int-wifi",
        "description": "WiFi & 802.1X Infrastructure CA",
        "dir": BASE_DIR / "int-wifi",
        "cert": BASE_DIR / "int-wifi" / "certs" / "int-wifi.cert.pem",
        "key": BASE_DIR / "int-wifi" / "private" / "int-wifi.key.pem",
        "chain": BASE_DIR / "int-wifi" / "certs" / "ca-chain.cert.pem",
        "crl": BASE_DIR / "int-wifi" / "crl" / "int-wifi.crl.pem",
        "crl_der": BASE_DIR / "int-wifi" / "crl" / "int-wifi.crl",
        "default_for": ["wifi", "radius", "8021x"],
    },
    "int-iot": {
        "name": "int-iot",
        "description": "IoT & Embedded Device CA",
        "dir": BASE_DIR / "int-iot",
        "cert": BASE_DIR / "int-iot" / "certs" / "int-iot.cert.pem",
        "key": BASE_DIR / "int-iot" / "private" / "int-iot.key.pem",
        "chain": BASE_DIR / "int-iot" / "certs" / "ca-chain.cert.pem",
        "crl": BASE_DIR / "int-iot" / "crl" / "int-iot.crl.pem",
        "crl_der": BASE_DIR / "int-iot" / "crl" / "int-iot.crl",
        "default_for": ["iot", "device", "mqtt"],
    },
}

# Database
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "rajlabs_ca.db"

# CA Defaults
CA_ORGANIZATION = os.getenv("CA_ORGANIZATION", "Rajlabs")
CA_COUNTRY = os.getenv("CA_COUNTRY", "IN")
CA_STATE = os.getenv("CA_STATE", "Karnataka")
CA_CITY = os.getenv("CA_CITY", "Bengaluru")

# ACME Config
ACME_ALLOW_PRIVATE_NETWORKS = os.getenv("ACME_ALLOW_PRIVATE_NETWORKS", "true").lower() in ("true", "1", "yes")
ACME_DEFAULT_INTERMEDIATE = os.getenv("ACME_DEFAULT_INTERMEDIATE", "int-server")
ACME_CERT_VALIDITY_DAYS = int(os.getenv("ACME_CERT_VALIDITY_DAYS", "90"))

# CRL & AIA Distribution Points (Multi-Domain Fallbacks)
CRL_DAYS_VALID = int(os.getenv("CRL_DAYS_VALID", "7"))
DEFAULT_CRL_FALLBACKS = [
    "http://certs.rajlabs.in",
    "http://crl.rajlabs.in",
    "http://pki.rajlabs.in",
]
_crl_fallbacks_env = os.getenv("CRL_FALLBACK_URLS", "")
if _crl_fallbacks_env:
    CRL_FALLBACK_URLS = [u.strip().rstrip("/") for u in _crl_fallbacks_env.split(",") if u.strip()]
else:
    CRL_FALLBACK_URLS = DEFAULT_CRL_FALLBACKS

DEFAULT_OCSP_FALLBACKS = [
    "http://certs.rajlabs.in/ocsp",
    "http://ocsp.rajlabs.in",
    "http://pki.rajlabs.in/ocsp",
]
_ocsp_fallbacks_env = os.getenv("OCSP_FALLBACK_URLS", "")
if _ocsp_fallbacks_env:
    OCSP_FALLBACK_URLS = [u.strip().rstrip("/") for u in _ocsp_fallbacks_env.split(",") if u.strip()]
else:
    OCSP_FALLBACK_URLS = DEFAULT_OCSP_FALLBACKS
