# Contributing to Rajlabs-CA

Thank you for your interest in contributing to **Rajlabs-CA**! We welcome bug reports, documentation improvements, feature requests, and pull requests.

---

## 🛠️ Development Setup

### Prerequisites
* Docker and Docker Compose v2+
* Python 3.12+
* OpenSSL CLI

### Clone & Configure
```bash
git clone https://github.com/<your-username>/Rajlabs-CA.git
cd Rajlabs-CA

# Copy configuration template
cp .env.example .env
```

---

## 🧪 Testing & Verification

Before submitting any Pull Request, ensure that all tests and security audits pass:

### 1. Run Pre-Commit Security Audit
Verify that no private keys or secrets are staged or tracked:
```bash
python3 scripts/verify_security.py
```
> [!IMPORTANT]
> If `verify_security.py` fails, your commit contains sensitive keys or tokens. You must resolve all issues before committing.

### 2. Verify Cryptographic Signer & CRL Engine
Test leaf certificate issuance and CRL re-generation:
```bash
python3 cli/certctl.py status
python3 cli/certctl.py cert create --cn test-ci.rajlabs.local --san test-ci.rajlabs.local,127.0.0.1 --days 1
python3 cli/certctl.py cert list
```

### 3. Build & Test Docker Container
```bash
docker compose build
docker compose up -d
curl -I http://localhost:8000/
docker compose down
```

---

## 📋 Pull Request Guidelines

1. **Create a topic branch**: `git checkout -b feature/my-new-feature`
2. **Commit with clear messages**: Follow standard conventional commits (e.g. `feat: add OCSP stapling support`, `fix: handle edge case in CRL nextUpdate`).
3. **Never commit `.key`, `.key.pem`, or `.env` files**: Strict automated pre-commit scanning will fail.
4. **Update Documentation**: Ensure relevant sections of `README.md` or `CHANGELOG.md` are updated.
5. **Open a PR**: Push to your fork and submit a Pull Request to `main`.
