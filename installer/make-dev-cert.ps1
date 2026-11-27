# One-time setup: creates a free self-signed code-signing certificate and trusts it on THIS PC only.
# Run in an elevated (Administrator) PowerShell:   .\installer\make-dev-cert.ps1
# Result: AegisGuard installers/apps signed with it show "Darshil Patel" instead of "Unknown publisher" on this PC.
# Other PCs will NOT trust it (that needs a real certificate, e.g. SignPath Foundation for open source).
# The .pfx contains your PRIVATE KEY: keep it outside the repo, never share it.
param([string]$Subject = "CN=Darshil Patel, O=AegisGuard", [string]$OutDir = "$env:USERPROFILE\AegisGuard-signing")
$ErrorActionPreference = "Stop"
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Run this script from an elevated (Administrator) PowerShell." }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$pwd1 = Read-Host "Choose a password for the signing key file" -AsSecureString

$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject -KeyAlgorithm RSA -KeyLength 3072 `
    -HashAlgorithm SHA256 -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(5) -CertStoreLocation Cert:\CurrentUser\My

$pfx = Join-Path $OutDir "aegisguard-signing.pfx"
$cer = Join-Path $OutDir "aegisguard-signing.cer"
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $pwd1 | Out-Null
Export-Certificate -Cert $cert -FilePath $cer | Out-Null

# Trust on this PC: root store (makes the chain valid) + Trusted Publishers (no publisher prompts)
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null

# Base64 text for the GitHub secret so CI releases are signed too
$b64 = Join-Path $OutDir "aegisguard-signing.pfx.base64.txt"
[Convert]::ToBase64String([IO.File]::ReadAllBytes($pfx)) | Set-Content -Encoding ascii $b64

Write-Host ""
Write-Host "Done. Files in $OutDir"
Write-Host "Next: GitHub repo > Settings > Secrets and variables > Actions > New repository secret:"
Write-Host "  AEGISGUARD_SIGN_PFX_BASE64  = contents of aegisguard-signing.pfx.base64.txt"
Write-Host "  AEGISGUARD_SIGN_PASSWORD    = the password you just chose"
Write-Host "Then delete the .base64.txt file. Keep the .pfx somewhere safe (it is your private key)."
