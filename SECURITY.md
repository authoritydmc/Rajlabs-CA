# Security Policy & Architecture

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

---

## 🔒 The Zero-Leak Security Architecture

**Rajlabs-CA** is designed from the ground up for strict cryptographic isolation and enterprise-grade security.

### 1. Offline Root CA Model (Defense-in-Depth)
* **Never in the Runtime Container**: The Root CA private key (`root-ca/private/root-ca.key.pem`) is **NEVER mounted** into the Docker container.
* **Never in Git**: The `.gitignore` strictly prohibits committing any private keys, passphrases, or `.key.pem` files.
* **Separation of Roles**: The Root CA signs only the Intermediate CAs (`int-server`, `int-wifi`, `int-iot`). Routine operations (leaf certificate issuance, ACME automation, and CRL signing) are handled exclusively by the intermediate CAs. If the runtime container is ever compromised, the Root CA remains completely untouched.

### 2. Pre-Commit Secret Scanner
This repository includes an automated security audit script ([`scripts/verify_security.py`](scripts/verify_security.py)) that inspects the working tree and staged Git index before every commit:
* Scans for private key headers (`-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN PRIVATE KEY-----`, etc.).
* Scans for sensitive filename patterns (`*.key`, `*.key.pem`, `*.pfx`, `*.p12`).
* Aborts commits immediately if any sensitive file is detected.

To verify your repository before pushing:
```bash
python3 scripts/verify_security.py
```

### 3. Proper Key Storage Recommendations
* Store the Root CA private key on an encrypted, air-gapped storage medium (e.g. encrypted USB drive, YubiKey HSM, or secure vault).
* Ensure file permissions for intermediate keys on the host machine are restricted (`chmod 600 int-*/private/*.key.pem`).
* Set strong `API_KEY` and `ADMIN_PASSWORD` in your `.env` file before deploying to production.

---

## Reporting a Vulnerability

We take the security of Rajlabs-CA very seriously. If you discover a security vulnerability, please do **NOT** open a public issue.

Instead, please report it privately:
1. Email the maintainer or submit a private security advisory on GitHub under the **Security** tab.
2. Include detailed reproduction steps and affected versions.
3. You will receive an initial response within **48 hours**.
4. We kindly request responsible disclosure until a patch has been published.
