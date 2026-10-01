import os
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives import hashes

from app.config import (
    BASE_URL,
    CA_ORGANIZATION,
    HOST,
    PORT,
    ROOT_CERT_PATH,
    INTERMEDIATES
)
from app.database.database import init_db
from app.crypto.ca_manager import ca_manager
from app.acme.router import acme_router
from app.api.certificates import cert_router
from app.api.ca_endpoints import ca_api_router
from app.api.onboarding import onboarding_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database and load CAs
    init_db()
    ca_manager.load_cas()
    # Rebuild CRLs on startup if missing
    for ca_key in INTERMEDIATES.keys():
        try:
            if ca_manager.intermediates.get(ca_key, {}).get("cert"):
                ca_manager.rebuild_crl(ca_key)
        except Exception:
            pass
    yield

app = FastAPI(
    title=f"{CA_ORGANIZATION} Certificate Authority",
    description="Enterprise Private Certificate Authority with ACME v2 (RFC 8555), RFC 5280 CRL Distribution, and Multi-OS Trust Center",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS for local API access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Mount Routers
app.include_router(acme_router)
app.include_router(cert_router)
app.include_router(ca_api_router)
app.include_router(onboarding_router)

@app.get("/", response_class=HTMLResponse, tags=["Public Portal"])
def public_landing_page(request: Request):
    """Renders the public trust landing page with OS onboarding guides."""
    root_fp = "NOT LOADED"
    root_subject = "Not Available"
    root_serial = "N/A"

    if ca_manager.root_cert:
        cert = ca_manager.root_cert
        fp_raw = cert.fingerprint(hashes.SHA256()).hex().upper()
        root_fp = ":".join(fp_raw[i:i+2] for i in range(0, len(fp_raw), 2))
        root_subject = cert.subject.rfc4514_string()
        root_serial = hex(cert.serial_number)[2:]

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "org_name": CA_ORGANIZATION,
            "base_url": BASE_URL,
            "root_fp": root_fp,
            "root_subject": root_subject,
            "root_serial": root_serial,
        }
    )

@app.get("/dashboard", response_class=HTMLResponse, tags=["Admin Portal"])
def cert_manager_dashboard(request: Request):
    """Renders the Certificate Management CRUD Dashboard."""
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "org_name": CA_ORGANIZATION,
            "base_url": BASE_URL,
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=True)
