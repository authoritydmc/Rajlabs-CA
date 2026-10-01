import uuid
from fastapi import APIRouter, Response, HTTPException
from app.config import BASE_URL, CA_ORGANIZATION
from app.crypto.ca_manager import ca_manager

onboarding_router = APIRouter(tags=["Device Onboarding & Trust Installers"])

@onboarding_router.get("/apple/rajlabs-root.mobileconfig")
def get_apple_profile():
    """
    Generates an Apple Configuration Profile (.mobileconfig) for 1-tap installation
    and trust on iOS, iPadOS, and macOS.
    """
    if not ca_manager.root_cert_pem:
        raise HTTPException(status_code=404, detail="Root CA not loaded")

    # Clean cert payload (strip headers/newlines for DER b64 inside plist)
    cert_lines = [
        line.strip() for line in ca_manager.root_cert_pem.splitlines()
        if line.strip() and not line.startswith("-----")
    ]
    raw_cert_b64 = "".join(cert_lines)

    profile_uuid = str(uuid.uuid4())
    payload_uuid = str(uuid.uuid4())

    mobileconfig_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadCertificateFileName</key>
            <string>{CA_ORGANIZATION}-Root-CA.crt</string>
            <key>PayloadContent</key>
            <data>
            {raw_cert_b64}
            </data>
            <key>PayloadDescription</key>
            <string>Installs {CA_ORGANIZATION} Root Certificate Authority to enable HTTPS trust for local network services.</string>
            <key>PayloadDisplayName</key>
            <string>{CA_ORGANIZATION} Root CA</string>
            <key>PayloadIdentifier</key>
            <string>com.{CA_ORGANIZATION.lower()}.rootca.credential.{payload_uuid}</string>
            <key>PayloadType</key>
            <string>cfa40a45-6677-448c-9a48-a006cb5561a0</string>
            <key>PayloadUUID</key>
            <string>{payload_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Configures trust for {CA_ORGANIZATION} Internal Root Certificate Authority.</string>
    <key>PayloadDisplayName</key>
    <string>{CA_ORGANIZATION} Root CA Trust Profile</string>
    <key>PayloadIdentifier</key>
    <string>com.{CA_ORGANIZATION.lower()}.rootca.profile.{profile_uuid}</string>
    <key>PayloadOrganization</key>
    <string>{CA_ORGANIZATION}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{profile_uuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
"""
    return Response(
        content=mobileconfig_xml.strip(),
        media_type="application/x-apple-aspen-config",
        headers={"Content-Disposition": f'attachment; filename="{CA_ORGANIZATION.lower()}-root-ca.mobileconfig"'}
    )

@onboarding_router.get("/install.sh")
def get_linux_install_script():
    """
    Dynamic shell script for 1-command Linux and macOS trust installation.
    Usage: curl -fsSL https://<ca-server>/install.sh | sudo bash
    """
    cert_url = f"{BASE_URL}/api/v1/ca/root/cert"
    script = f"""#!/usr/bin/env bash
# ==============================================================================
# {CA_ORGANIZATION} Root CA Automated Trust Installer for Linux & macOS
# ==============================================================================
set -e

RED='\\033[0;31m'
GREEN='\\033[0;32m'
CYAN='\\033[0;36m'
NC='\\033[0m'

echo -e "${{CYAN}}======================================================${{NC}}"
echo -e "${{CYAN}} 🔒 Installing {CA_ORGANIZATION} Root Certificate Authority ${{NC}}"
echo -e "${{CYAN}}======================================================${{NC}}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${{RED}}[-] Please run as root (e.g. curl -fsSL {BASE_URL}/install.sh | sudo bash)${{NC}}"
  exit 1
fi

TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

echo -e "[*] Downloading Root CA from {cert_url}..."
curl -fsSL "{cert_url}" -o "$TEMP_DIR/rajlabs-root-ca.crt"

OS_NAME="$(uname -s)"
if [ "$OS_NAME" = "Darwin" ]; then
    echo -e "[*] Detected macOS. Adding to System Keychain..."
    security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$TEMP_DIR/rajlabs-root-ca.crt"
    echo -e "${{GREEN}}[+] {CA_ORGANIZATION} Root CA installed successfully in macOS System Keychain!${{NC}}"
    exit 0
fi

# Detect Linux Distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
    LIKE=$ID_LIKE
else
    DISTRO="unknown"
    LIKE="unknown"
fi

echo -e "[*] Detected Linux distribution: $DISTRO"

if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ] || echo "$LIKE" | grep -q "debian"; then
    cp "$TEMP_DIR/rajlabs-root-ca.crt" /usr/local/share/ca-certificates/rajlabs-root-ca.crt
    update-ca-certificates
elif [ "$DISTRO" = "fedora" ] || [ "$DISTRO" = "rhel" ] || [ "$DISTRO" = "centos" ] || [ "$DISTRO" = "rocky" ] || [ "$DISTRO" = "alma" ] || echo "$LIKE" | grep -q "rhel"; then
    cp "$TEMP_DIR/rajlabs-root-ca.crt" /etc/pki/ca-trust/source/anchors/rajlabs-root-ca.crt
    update-ca-trust
elif [ "$DISTRO" = "arch" ] || echo "$LIKE" | grep -q "arch"; then
    trust anchor --store "$TEMP_DIR/rajlabs-root-ca.crt"
elif [ "$DISTRO" = "alpine" ]; then
    cp "$TEMP_DIR/rajlabs-root-ca.crt" /usr/local/share/ca-certificates/rajlabs-root-ca.crt
    update-ca-certificates
else
    echo -e "${{RED}}[-] Unrecognized distro. Falling back to Debian/Ubuntu standard...${{NC}}"
    mkdir -p /usr/local/share/ca-certificates
    cp "$TEMP_DIR/rajlabs-root-ca.crt" /usr/local/share/ca-certificates/rajlabs-root-ca.crt
    update-ca-certificates 2>/dev/null || true
fi

echo -e "${{GREEN}}[+] {CA_ORGANIZATION} Root CA installed and trusted system-wide!${{NC}}"
"""
    return Response(content=script, media_type="text/x-shellscript")

@onboarding_router.get("/install.ps1")
def get_windows_install_script():
    """
    Dynamic PowerShell script for 1-command Windows trust installation.
    Usage: irm https://<ca-server>/install.ps1 | iex
    """
    cert_url = f"{BASE_URL}/api/v1/ca/root/cert"
    script = f"""# ==============================================================================
# {CA_ORGANIZATION} Root CA Automated Trust Installer for Windows
# ==============================================================================
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " 🔒 Installing {CA_ORGANIZATION} Root Certificate Authority" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

$certUrl = "{cert_url}"
$tempFile = [System.IO.Path]::GetTempFileName() + ".crt"

try {{
    Write-Host "[*] Downloading Root CA from $certUrl..." -ForegroundColor Yellow
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $certUrl -OutFile $tempFile -UseBasicParsing

    Write-Host "[*] Importing certificate into LocalMachine\\Root (Trusted Root Certification Authorities)..." -ForegroundColor Yellow
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $cert.Import($tempFile)

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open("ReadWrite")
    $store.Add($cert)
    $store.Close()

    Write-Host "`n[+] {CA_ORGANIZATION} Root CA installed and trusted successfully!" -ForegroundColor Green
    Write-Host "    Subject: $($cert.Subject)"
    Write-Host "    Thumbprint: $($cert.Thumbprint)"
}}
catch {{
    Write-Host "`n[-] Error installing certificate: $_" -ForegroundColor Red
    Write-Host "    Ensure you are running PowerShell as Administrator." -ForegroundColor Yellow
}}
finally {{
    if (Test-Path $tempFile) {{ Remove-Item $tempFile -Force }}
}}
"""
    return Response(content=script, media_type="text/plain")
