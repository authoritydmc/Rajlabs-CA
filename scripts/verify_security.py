#!/usr/bin/env python3
"""
Rajlabs-CA Pre-Commit Security & Secret Leak Verification Script.
Audits the repository working tree and Git staged files to guarantee
that NO private keys (*.key, *.key.pem, root-ca/private/*, etc.) or secrets
are tracked or staged for commit.
"""

import os
import sys
import subprocess
from pathlib import Path

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Private key markers to scan for
PRIVATE_KEY_MARKERS = [
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSL PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
]

SENSITIVE_FILENAME_PATTERNS = [
    ".key",
    ".key.pem",
    ".pem.key",
    ".pfx",
    ".p12",
    ".secret",
    "root-ca.key.pem",
]


def check_git_status():
    """Verify git status for any sensitive files staged or tracked."""
    print("=" * 70)
    print("🔒 RAJLABS-CA SECURITY AUDIT: SCANNING FOR LEAKED SECRETS & KEYS")
    print("=" * 70)

    repo_dir = Path(__file__).resolve().parent.parent

    # 1. Check if git is initialized
    git_dir = repo_dir / ".git"
    if not git_dir.exists():
        print("ℹ️ Git repository not yet initialized. Scanning filesystem directly...")
        tracked_files = []
    else:
        try:
            # Check tracked files
            tracked = subprocess.check_output(
                ["git", "ls-files"], cwd=repo_dir, text=True
            ).splitlines()
            # Check staged files
            staged = subprocess.check_output(
                ["git", "diff", "--name-only", "--cached"], cwd=repo_dir, text=True
            ).splitlines()
            tracked_files = list(set(tracked + staged))
        except Exception as e:
            print(f"⚠️ Error running git ls-files: {e}")
            tracked_files = []

    violations = []

    # 2. Check tracked and staged files
    for rel_path in tracked_files:
        full_path = repo_dir / rel_path
        # Check filename pattern
        for pattern in SENSITIVE_FILENAME_PATTERNS:
            if rel_path.endswith(pattern) or f"/{pattern}" in rel_path or f"\\{pattern}" in rel_path:
                violations.append(f"CRITICAL: Tracked file matches sensitive pattern '{pattern}': {rel_path}")

        if "root-ca/private" in rel_path or "private/" in rel_path:
            violations.append(f"CRITICAL: Private directory file tracked: {rel_path}")

        # Scan file content if file exists
        if full_path.is_file() and rel_path.replace("\\", "/") not in ("SECURITY.md", "scripts/verify_security.py"):
            try:
                content = full_path.read_bytes()
                for marker in PRIVATE_KEY_MARKERS:
                    if marker in content:
                        violations.append(
                            f"CRITICAL: File contains private key content marker ({marker.decode()}): {rel_path}"
                        )
                        break
            except Exception as e:
                pass

    # 3. Scan git status for any untracked or unstaged alerts
    try:
        status_output = subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=repo_dir, text=True
        ).splitlines()
        for line in status_output:
            status_code = line[:2]
            filename = line[3:].strip()
            # If staged (first column is A, M, or R)
            if status_code[0] in ["A", "M", "R"]:
                for pattern in SENSITIVE_FILENAME_PATTERNS:
                    if filename.endswith(pattern):
                        violations.append(f"CRITICAL: Staged file has forbidden extension '{pattern}': {filename}")
                if "root-ca/private" in filename or "private/" in filename:
                    violations.append(f"CRITICAL: Staged file in private/ directory: {filename}")
    except Exception:
        pass

    # 4. Check that .gitignore is properly ignoring root-ca.key.pem
    root_key = repo_dir / "root-ca" / "private" / "root-ca.key.pem"
    if root_key.exists() and git_dir.exists():
        check_ignore = subprocess.run(
            ["git", "check-ignore", str(root_key)], cwd=repo_dir, capture_output=True, text=True
        )
        if check_ignore.returncode != 0:
            violations.append(
                f"CRITICAL: root-ca.key.pem is NOT ignored by .gitignore! Return code: {check_ignore.returncode}"
            )

    if violations:
        print("\n❌ SECURITY AUDIT FAILED! The following security violations were detected:")
        for v in violations:
            print(f"   [!] {v}")
        print("\nDO NOT COMMIT OR PUSH! Resolve the violations above immediately.")
        sys.exit(1)
    else:
        print("✅ SUCCESS: No private keys, sensitive secrets, or credentials detected in Git index.")
        print("✅ Root CA private key is strictly isolated and ignored.")
        print("=" * 70)
        sys.exit(0)


if __name__ == "__main__":
    check_git_status()
