<#
.SYNOPSIS
    Generates Intermediate CAs signed by the Root CA in Rajlabs-CA.
    If an Intermediate CA already exists, prompts the user interactively with options:
      [S] Skip (keep existing certificate)
      [R] Revoke old cert with Root CA, archive old files, and issue new Intermediate
      [O] Overwrite directly without revocation
      [A] Abort script
#>

param(
    [string]$Country = "IN",
    [string]$State = "Karnataka",
    [string]$City = "Bengaluru",
    [string]$Org = "Rajlabs",
    [int]$DaysIntermediate = 3650,
    [ValidateSet("Prompt", "Skip", "RevokeAndReissue", "Overwrite")]
    [string]$ExistingAction = "Prompt"
)

$ErrorActionPreference = "Stop"

# Detect OpenSSL path
$OpenSSLCmd = Get-Command openssl -ErrorAction SilentlyContinue
if ($OpenSSLCmd) {
    $OpenSSL = $OpenSSLCmd.Source
} elseif (Test-Path "C:\Program Files\Git\usr\bin\openssl.exe") {
    $OpenSSL = "C:\Program Files\Git\usr\bin\openssl.exe"
} else {
    throw "OpenSSL executable could not be found. Please ensure OpenSSL or Git for Windows is installed."
}

Write-Host "Using OpenSSL at: $OpenSSL" -ForegroundColor Cyan

$baseDir = $PSScriptRoot
Set-Location $baseDir

$rootKey       = "$baseDir\root-ca\private\root-ca.key.pem"
$rootCert      = "$baseDir\root-ca\certs\root-ca.cert.pem"
$rootCnf       = "$baseDir\root-ca\openssl.cnf"
$rootIndex     = "$baseDir\root-ca\index.txt"
$rootCrlDir    = "$baseDir\root-ca\crl"
$rootCrlFile   = "$rootCrlDir\root-ca.crl.pem"
$rootCrlNumber = "$baseDir\root-ca\crlnumber"

# Step 1: Ensure Root CA exists - NEVER regenerate if already present!
if ((Test-Path $rootKey) -and (Test-Path $rootCert)) {
    Write-Host "`n[1/3] Existing Root CA found! Preserving existing Root CA." -ForegroundColor Green
    Write-Host "      Root Key : $rootKey"
    Write-Host "      Root Cert: $rootCert"
} else {
    Write-Host "`n[1/3] Root CA not found. Generating new Root CA..." -ForegroundColor Yellow
    & $OpenSSL genrsa -out $rootKey 4096
    & $OpenSSL req -config $rootCnf -key $rootKey -new -x509 -days 7300 -sha256 -extensions v3_ca -out $rootCert
    Write-Host "      Root CA generated at: $rootCert" -ForegroundColor Green
}

# Ensure root infrastructure files exist
if (-not (Test-Path $rootIndex)) {
    [System.IO.File]::WriteAllBytes($rootIndex, [byte[]]@())
} elseif ((Get-Item $rootIndex).Length -eq 2) {
    [System.IO.File]::WriteAllBytes($rootIndex, [byte[]]@())
}

if (-not (Test-Path $rootCrlDir)) {
    New-Item -ItemType Directory -Path $rootCrlDir -Force | Out-Null
}
if (-not (Test-Path $rootCrlNumber)) {
    Set-Content -Path $rootCrlNumber -Value "1000"
}

# Helper: Generate CRL
function Update-RootCrl {
    Write-Host "      Generating updated Root CRL: $rootCrlFile" -ForegroundColor Cyan
    & $OpenSSL ca -config $rootCnf -gencrl -out $rootCrlFile
}

# Step 2: Intermediate CAs to process
$intermediates = @(
    @{ Name = "int-server"; CN = "Rajlabs Server Intermediate CA"; OU = "Rajlabs Server Infrastructure" },
    @{ Name = "int-wifi";   CN = "Rajlabs WiFi Intermediate CA";   OU = "Rajlabs WiFi Infrastructure" },
    @{ Name = "int-iot";    CN = "Rajlabs IoT Intermediate CA";    OU = "Rajlabs IoT Infrastructure" }
)

Write-Host "`n[2/3] Processing Intermediate CAs..." -ForegroundColor Yellow

foreach ($ca in $intermediates) {
    $name = $ca.Name
    $caDir = "$baseDir\$name"
    $keyFile   = "$caDir\private\$name.key.pem"
    $csrFile   = "$caDir\csr\$name.csr.pem"
    $certFile  = "$caDir\certs\$name.cert.pem"
    $chainFile = "$caDir\certs\ca-chain.cert.pem"
    $archiveDir = "$caDir\archive"

    Write-Host "`n  ----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  --> Processing Intermediate CA: $name" -ForegroundColor Cyan

    # Ensure intermediate directory structure
    if (-not (Test-Path "$caDir\index.txt")) { [System.IO.File]::WriteAllBytes("$caDir\index.txt", [byte[]]@()) }
    if (-not (Test-Path "$caDir\serial"))    { Set-Content -Path "$caDir\serial" -Value "1000" }

    # Check if this intermediate already exists
    if ((Test-Path $keyFile) -and (Test-Path $certFile)) {
        # Determine action
        $chosenAction = $ExistingAction

        if ($chosenAction -eq "Prompt") {
            Write-Host "      [!] Intermediate '$name' already has an existing certificate and private key!" -ForegroundColor Yellow
            Write-Host "          Certificate: $certFile"
            
            $promptText = @"
      What would you like to do with '$name'?
        [S] Skip (keep existing certificate)
        [R] Revoke old cert with Root CA, archive old files, and issue new Intermediate
        [O] Overwrite (issue new cert without revoking old cert)
        [A] Abort entire script
      Choice (default: S): 
"@
            $userChoice = (Read-Host -Prompt $promptText).Trim().ToUpper()
            switch ($userChoice) {
                "R" { $chosenAction = "RevokeAndReissue" }
                "O" { $chosenAction = "Overwrite" }
                "A" { 
                    Write-Host "Aborted by user." -ForegroundColor Red
                    return 
                }
                Default { $chosenAction = "Skip" }
            }
        }

        if ($chosenAction -eq "Skip") {
            Write-Host "      [SKIP] Preserving existing certificate for $name." -ForegroundColor DarkGray
            continue
        }

        if ($chosenAction -eq "RevokeAndReissue") {
            Write-Host "      [REVOKE] Revoking old certificate in Root CA database..." -ForegroundColor Yellow
            & $OpenSSL ca -config $rootCnf -revoke $certFile -crl_reason superseded
            Update-RootCrl

            # Archive old certificate & key
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            if (-not (Test-Path $archiveDir)) { New-Item -ItemType Directory -Path $archiveDir -Force | Out-Null }
            Move-Item -Path $certFile -Destination "$archiveDir\$name-$timestamp.cert.pem" -Force
            if (Test-Path $csrFile) {
                Move-Item -Path $csrFile -Destination "$archiveDir\$name-$timestamp.csr.pem" -Force
            }
            Write-Host "      Archived old cert and CSR to: $archiveDir" -ForegroundColor Green
        }
    }

    # Generate Private Key if missing (or keep existing private key if overwriting/reissuing)
    if (-not (Test-Path $keyFile)) {
        Write-Host "      Generating new private key: $keyFile"
        & $OpenSSL genrsa -out $keyFile 4096
    } else {
        Write-Host "      Using private key: $keyFile"
    }

    # Generate CSR
    Write-Host "      Generating CSR: $csrFile"
    $subj = "/C=$Country/ST=$State/L=$City/O=$Org/OU=$($ca.OU)/CN=$($ca.CN)"
    & $OpenSSL req -new -sha256 -key $keyFile -out $csrFile -subj $subj

    # Sign CSR with Root CA
    Write-Host "      Signing Intermediate CA with Root CA..."
    & $OpenSSL ca -config $rootCnf `
                  -extensions v3_intermediate_ca `
                  -days $DaysIntermediate `
                  -notext `
                  -md sha256 `
                  -in $csrFile `
                  -out $certFile `
                  -batch

    # Verify certificate against Root CA
    Write-Host "      Verifying intermediate certificate against root CA..."
    & $OpenSSL verify -CAfile $rootCert $certFile

    # Create full chain (Intermediate + Root)
    Get-Content $certFile, $rootCert | Set-Content -Path $chainFile
    Write-Host "      [OK] Chain created at: $chainFile" -ForegroundColor Green
}

Write-Host "`n[3/3] Done! Intermediate CA workflow finished successfully." -ForegroundColor Green
