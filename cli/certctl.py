#!/usr/bin/env python3
"""
Rajlabs-CA CLI Management Tool (certctl)
Unified command-line interface for certificate issuance, renewal, revocation,
CRL maintenance, and automated OS trust installation.
"""

import os
import sys
import argparse
import json
import subprocess
import shutil
from pathlib import Path

# Add project root to sys.path so app packages are importable in local mode
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

def get_ca_manager():
    from app.database.database import init_db
    from app.crypto.ca_manager import ca_manager
    init_db()
    return ca_manager

def cmd_status(args):
    """Displays health, Root CA status, and certificate metrics."""
    mgr = get_ca_manager()
    from app.database.database import db_get_stats
    stats = db_get_stats()

    print("=" * 65)
    print("🔒 RAJLABS-CA STATUS & HEALTH")
    print("=" * 65)
    if mgr.root_cert:
        from cryptography.hazmat.primitives import hashes
        fp = ":".join(mgr.root_cert.fingerprint(hashes.SHA256()).hex().upper()[i:i+2] for i in range(0, 64, 2))
        print(f"Root CA Subject   : {mgr.root_cert.subject.rfc4514_string()}")
        print(f"Root CA Serial    : {hex(mgr.root_cert.serial_number)[2:]}")
        print(f"Root CA SHA-256   : {fp}")
        not_after = getattr(mgr.root_cert, "not_valid_after_utc", mgr.root_cert.not_valid_after)
        print(f"Root CA Valid To  : {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    else:
        print("Root CA           : NOT LOADED")

    print("-" * 65)
    print("Intermediate CAs:")
    for name, ca in mgr.intermediates.items():
        loaded = "✅ ACTIVE" if ca.get("cert") else "❌ NOT LOADED"
        print(f"  • {name:<12} : {loaded} ({ca['description']})")

    print("-" * 65)
    print(f"Certificates Active  : {stats['active']}")
    print(f"Certificates Revoked : {stats['revoked']}")
    print(f"Certificates Expired : {stats['expired']}")
    print(f"Total Issued         : {stats['total']}")
    print("=" * 65)

def cmd_root_get(args):
    """Outputs or writes the Root CA public certificate."""
    mgr = get_ca_manager()
    if not mgr.root_cert_pem:
        print("[-] Root CA certificate not available.", file=sys.stderr)
        sys.exit(1)
    if args.out:
        Path(args.out).write_text(mgr.root_cert_pem)
        print(f"[+] Root CA certificate written to: {args.out}")
    else:
        print(mgr.root_cert_pem)

def cmd_root_install(args):
    """Installs the Root CA certificate into the current operating system trust store."""
    mgr = get_ca_manager()
    if not mgr.root_cert_pem:
        print("[-] Root CA certificate not available.", file=sys.stderr)
        sys.exit(1)

    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".crt", delete=False) as f:
        f.write(mgr.root_cert_pem.encode("utf-8"))
        temp_path = f.name

    try:
        if sys.platform == "darwin":
            print("[*] Detected macOS. Adding to System Keychain...")
            cmd = ["sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", temp_path]
            subprocess.check_call(cmd)
            print("[+] Root CA trusted in macOS System Keychain.")
        elif sys.platform.startswith("linux"):
            print("[*] Detected Linux. Installing to system anchors...")
            if Path("/etc/debian_version").exists() or Path("/etc/lsb-release").exists():
                target = Path("/usr/local/share/ca-certificates/rajlabs-root-ca.crt")
                subprocess.check_call(["sudo", "cp", temp_path, str(target)])
                subprocess.check_call(["sudo", "update-ca-certificates"])
            elif Path("/etc/redhat-release").exists() or Path("/etc/fedora-release").exists():
                target = Path("/etc/pki/ca-trust/source/anchors/rajlabs-root-ca.crt")
                subprocess.check_call(["sudo", "cp", temp_path, str(target)])
                subprocess.check_call(["sudo", "update-ca-trust"])
            elif Path("/etc/arch-release").exists():
                subprocess.check_call(["sudo", "trust", "anchor", "--store", temp_path])
            else:
                target = Path("/usr/local/share/ca-certificates/rajlabs-root-ca.crt")
                subprocess.check_call(["sudo", "cp", temp_path, str(target)])
                subprocess.check_call(["sudo", "update-ca-certificates"])
            print("[+] Root CA installed and trusted system-wide.")
        elif sys.platform == "win32":
            print("[*] Detected Windows. Adding to LocalMachine\\Root...")
            cmd = ["certutil", "-addstore", "-f", "ROOT", temp_path]
            subprocess.check_call(cmd)
            print("[+] Root CA installed and trusted in Windows Cert Store.")
    finally:
        try:
            os.remove(temp_path)
        except Exception:
            pass

def cmd_cert_create(args):
    """Issues a new certificate."""
    mgr = get_ca_manager()
    sans = [s.strip() for s in args.san.split(",")] if args.san else []
    print(f"[*] Issuing certificate for CN={args.cn} (CA: {args.ca}, Profile: {args.profile})...")
    issued = mgr.issue_certificate(
        common_name=args.cn,
        sans=sans,
        ca_name=args.ca,
        profile_name=args.profile,
        key_algorithm=args.algorithm,
        days=args.days,
        issued_by="cli"
    )

    print("\n[+] Certificate issued successfully!")
    print(f"    Serial Number : {issued['serial_number']}")
    print(f"    Common Name   : {issued['common_name']}")
    print(f"    Fingerprint   : {issued['fingerprint_sha256']}")
    print(f"    Valid Until   : {issued['not_after']}")

    if args.out:
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{args.cn}.crt").write_text(issued["cert_pem"])
        (out_dir / f"{args.cn}-fullchain.crt").write_text(issued["chain_pem"])
        if issued.get("priv_key_pem"):
            (out_dir / f"{args.cn}.key").write_text(issued["priv_key_pem"])
        print(f"[+] Certificate files saved to directory: {out_dir.resolve()}")
    else:
        print("\n--- BEGIN CERTIFICATE ---")
        print(issued["cert_pem"])

def cmd_cert_list(args):
    """Lists certificates."""
    from app.database.database import db_list_certificates
    certs = db_list_certificates(ca_name=args.ca, status=args.status, query=args.search)

    if not certs:
        print("No certificates found.")
        return

    print(f"{'SERIAL':<18} {'COMMON NAME':<26} {'CA':<12} {'STATUS':<9} {'EXPIRES':<12}")
    print("-" * 80)
    for c in certs:
        exp = c['not_after'][:10]
        print(f"{c['serial_number']:<18} {c['common_name'][:25]:<26} {c['ca_name']:<12} {c['status']:<9} {exp:<12}")

def cmd_cert_revoke(args):
    """Revokes a certificate and rebuilds CRL."""
    mgr = get_ca_manager()
    print(f"[*] Revoking certificate {args.serial} (Reason: {args.reason})...")
    success = mgr.revoke_certificate(args.serial, reason=args.reason, actor="cli")
    if success:
        print(f"[+] Certificate {args.serial} revoked successfully. Intermediate CRL rebuilt.")
    else:
        print(f"[-] Failed to revoke certificate {args.serial} (not found or already revoked).", file=sys.stderr)
        sys.exit(1)

def cmd_cert_renew(args):
    """Renews a certificate."""
    mgr = get_ca_manager()
    print(f"[*] Renewing certificate {args.serial}...")
    renewed = mgr.renew_certificate(args.serial, new_days=args.days)
    print(f"[+] Certificate renewed successfully!")
    print(f"    New Serial  : {renewed['serial_number']}")
    print(f"    Valid Until : {renewed['not_after']}")

def cmd_crl_update(args):
    """Regenerates CRL for an intermediate CA."""
    mgr = get_ca_manager()
    cas = [args.ca] if args.ca else list(mgr.intermediates.keys())
    for ca_name in cas:
        print(f"[*] Rebuilding CRL for {ca_name}...")
        mgr.rebuild_crl(ca_name)
    print("[+] CRL(s) updated successfully.")

def main():
    parser = argparse.ArgumentParser(description="Rajlabs-CA PKI Management CLI (certctl)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # status
    p_status = subparsers.add_parser("status", help="Show PKI status and certificate metrics")
    p_status.set_defaults(func=cmd_status)

    # root
    p_root = subparsers.add_parser("root", help="Root CA operations")
    p_root_sub = p_root.add_subparsers(dest="subcommand", required=True)
    p_rget = p_root_sub.add_parser("get", help="Get Root CA public certificate")
    p_rget.add_argument("--out", "-o", help="File path to save Root CA certificate")
    p_rget.set_defaults(func=cmd_root_get)

    p_rinst = p_root_sub.add_parser("install", help="Install Root CA into host OS trust store")
    p_rinst.set_defaults(func=cmd_root_install)

    # cert
    p_cert = subparsers.add_parser("cert", help="Certificate operations")
    p_cert_sub = p_cert.add_subparsers(dest="subcommand", required=True)

    # cert create
    p_create = p_cert_sub.add_parser("create", help="Issue a new certificate")
    p_create.add_argument("--cn", required=True, help="Common Name (e.g. server.local)")
    p_create.add_argument("--san", help="Comma-separated Subject Alternative Names")
    p_create.add_argument("--ca", default="int-server", choices=["int-server", "int-wifi", "int-iot"], help="Intermediate CA to sign with")
    p_create.add_argument("--profile", default="server", choices=["server", "client", "wifi", "iot", "codesign"], help="Certificate usage profile")
    p_create.add_argument("--algorithm", default="rsa2048", choices=["rsa2048", "rsa4096", "p256", "ed25519"], help="Key algorithm")
    p_create.add_argument("--days", type=int, help="Validity duration in days")
    p_create.add_argument("--out", "-o", help="Output directory for .crt, .key, and fullchain")
    p_create.set_defaults(func=cmd_cert_create)

    # cert list
    p_list = p_cert_sub.add_parser("list", help="List issued certificates")
    p_list.add_argument("--ca", help="Filter by intermediate CA")
    p_list.add_argument("--status", choices=["VALID", "REVOKED", "EXPIRED"], help="Filter by status")
    p_list.add_argument("--search", "-q", help="Search query")
    p_list.set_defaults(func=cmd_cert_list)

    # cert revoke
    p_revoke = p_cert_sub.add_parser("revoke", help="Revoke a certificate")
    p_revoke.add_argument("serial", help="Serial number of certificate to revoke")
    p_revoke.add_argument("--reason", default="keyCompromise", help="RFC 5280 revocation reason")
    p_revoke.set_defaults(func=cmd_cert_revoke)

    # cert renew
    p_renew = p_cert_sub.add_parser("renew", help="Renew an existing certificate")
    p_renew.add_argument("serial", help="Serial number of certificate to renew")
    p_renew.add_argument("--days", type=int, help="New validity in days")
    p_renew.set_defaults(func=cmd_cert_renew)

    # crl
    p_crl = subparsers.add_parser("crl", help="CRL operations")
    p_crl_sub = p_crl.add_subparsers(dest="subcommand", required=True)
    p_crl_update = p_crl_sub.add_parser("update", help="Update/rebuild CRLs")
    p_crl_update.add_argument("--ca", choices=["int-server", "int-wifi", "int-iot"], help="Specific intermediate CA")
    p_crl_update.set_defaults(func=cmd_crl_update)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
