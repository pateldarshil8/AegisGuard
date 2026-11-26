# Builds AegisGuard and its Windows installer.
#   .\installer\build.ps1                 -> dist\AegisGuard\ and dist-installer\AegisGuardSetup-<version>.exe
#   .\installer\build.ps1 -SkipInstaller  -> only the PyInstaller folder (no Inno Setup needed)
# Optional signing: set AEGISGUARD_SIGN_PFX (path to a .pfx code-signing certificate) and AEGISGUARD_SIGN_PASSWORD.
param([switch]$SkipInstaller, [string]$Python = "")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# Use the project's virtual environment when it exists (the Microsoft Store Python has very long package paths
# that can break installs of large packages like PySide6).
if (-not $Python) {
    $venvPy = Join-Path $root ".venv\Scripts\python.exe"
    $Python = if (Test-Path $venvPy) { $venvPy } else { "python" }
}
Write-Host "==> Using Python: $Python"

function Invoke-Checked($cmd) {
    & $cmd[0] $cmd[1..($cmd.Length - 1)]
    if ($LASTEXITCODE -ne 0) { throw "Command failed ($LASTEXITCODE): $($cmd -join ' ')" }
}

function Sign-File($file) {
    if (-not $env:AEGISGUARD_SIGN_PFX) { return }
    $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if (-not $signtool) { Write-Warning "signtool.exe not found; skipping signing of $file"; return }
    Invoke-Checked @($signtool.Source, "sign", "/f", $env:AEGISGUARD_SIGN_PFX, "/p", $env:AEGISGUARD_SIGN_PASSWORD,
                     "/fd", "SHA256", "/tr", "http://timestamp.digicert.com", "/td", "SHA256", $file)
}

$version = & $Python -c "import sys; sys.path.insert(0, 'src'); import aegisguard; print(aegisguard.__version__)"
Write-Host "==> Building AegisGuard $version"

Write-Host "==> Installing build dependencies"
Invoke-Checked @($Python, "-m", "pip", "install", "--quiet", "-e", ".[ui,build]")

Write-Host "==> Generating icon"
Invoke-Checked @($Python, "installer\make_icon.py")

Write-Host "==> Bundling with PyInstaller"
Invoke-Checked @($Python, "-m", "PyInstaller", "--noconfirm", "--clean", "--distpath", "dist", "--workpath", "build", "installer\aegisguard.spec")
if (-not (Test-Path "dist\AegisGuard\AegisGuard.exe")) { throw "PyInstaller did not produce dist\AegisGuard\AegisGuard.exe" }
Sign-File "dist\AegisGuard\AegisGuard.exe"
Sign-File "dist\AegisGuard\aegisguard-cli.exe"
Write-Host "    Portable build ready: dist\AegisGuard\AegisGuard.exe"

if ($SkipInstaller) { exit 0 }

$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
          "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
    Write-Host "Inno Setup 6 not found. Install it (free) with:  winget install JRSoftware.InnoSetup"
    Write-Host "Then run this script again."
    exit 1
}
Write-Host "==> Building installer with Inno Setup"
Invoke-Checked @($iscc, "/DMyAppVersion=$version", "installer\AegisGuard.iss")
$setup = "dist-installer\AegisGuardSetup-$version.exe"
Sign-File $setup
Write-Host "==> Done: $setup"
