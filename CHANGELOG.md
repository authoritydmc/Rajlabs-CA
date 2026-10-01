# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-09-30

### Added
- **Core PKI Architecture**:
  - Offline Root CA architecture with multi-intermediate hierarchy (`int-server`, `int-wifi`, `int-iot`).
  - Native Python `cryptography.x509` based RFC 5280 certificate signer and manager.
  - Zero-leak private key defense model: Root CA private key is never mounted in Docker and strictly ignored in Git.
- **Certificate Lifecycle (CRUD)**:
  - Certificate issuance supporting preset profiles: Web Server TLS, Client mTLS, WiFi 802.1X (RADIUS), IoT devices, and Code Signing.
  - Multi-SAN support for DNS domains and IPv4/IPv6 addresses.
  - Server-side key generation (RSA 2048/4096, ECDSA P-256/P-384, Ed25519) and Zero-Trust client CSR uploads.
  - One-click certificate renewal.
  - Revocation handling with RFC 5280 reason codes (`keyCompromise`, `superseded`, etc.) and instant CRL re-generation.
  - Certificate export formats: PEM (`.crt`, `.key`, fullchain) and PKCS#12 / PFX (`.pfx`) with custom password.
- **ACME v2 Protocol Engine (RFC 8555)**:
  - Full support for `certbot`, Caddy, Traefik, acme.sh, and Nginx Proxy Manager.
  - Endpoints: `/acme/directory`, `/acme/new-nonce`, `/acme/new-account`, `/acme/new-order`, `/acme/authz`, `/acme/chall`, `/acme/order/finalize`, `/acme/cert`.
  - Homelab & Intranet auto-validation mode for private domain namespaces without public DNS.
- **Public Trust Center & Device Onboarding Portal**:
  - Responsive web landing page with SHA-256 fingerprint verification card.
  - Direct downloads for Root CA in PEM (`.crt`), binary DER (`.cer`), and Apple Configuration Profile (`.mobileconfig`).
  - Interactive multi-OS installation guides for Windows, macOS, iOS, Android, Linux (Ubuntu/Debian, RHEL/Fedora/Rocky, Arch, Alpine), Firefox, and runtimes (Java, Node.js, Python, Docker).
  - 1-liner copyable trust installer scripts (`curl ... | bash` and `irm ... | iex`).
- **REST API & Interactive Documentation**:
  - Full OpenAPI 3.0 / Swagger documentation at `/docs` and ReDoc at `/redoc`.
  - Certificate CRUD endpoints, CA metadata, CRL distribution, and server configuration generators.
- **Standalone CLI (`certctl`)**:
  - Unified CLI for PKI status, cert creation, listing, renewal, revocation, CRL rebuild, and automated OS trust installation.
- **Security & Pre-Commit Audit**:
  - `scripts/verify_security.py` pre-commit script preventing secret and key leaks.
  - Comprehensive `.gitignore` protecting all `.key` and `private/` directories.
- **Containerization**:
  - Self-contained `Dockerfile` and `docker-compose.yml` deployment.
