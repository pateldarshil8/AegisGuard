# AegisGuard

Endpoint security and system health suite for Windows 10/11, in one desktop app.

*Status: v1.0. Works, but it is a young project: it complements Windows Defender, it does not replace it.*

## What it does

| Area | What you get |
|---|---|
| **Malware scan** | Known-bad hashes (plus an optional downloadable threat feed), double-extension tricks, programs disguised as pictures/documents, suspicious scripts. Quarantine with restore. Scan types: Quick (common malware locations), Full (every local drive), Deep (full plus stricter checks), Custom (folders you pick); any scan can be stopped. |
| **Process check** | Windows process names running from the wrong folder, look-alike names, programs running from Temp/Downloads, suspicious PowerShell. |
| **Network** | Risky open ports and suspicious outbound connections. Block a program or IP in Windows Firewall (always asks first). |
| **Fixes** | Finds risky settings (UAC, SMBv1, Remote Desktop, Defender off, firewall off) and offers one-click fixes after you review the exact command. |
| **Background protection** | Watches Downloads/Desktop, re-checks processes and network, scheduled audits, tray alerts, start at sign-in. |
| **Disk cleanup** | Frees old temp/cache files and shows where your space is going. Never touches your documents. |
| **Security score & history** | Score per full check, trend, and what changed since last time. |

Everything that changes your system asks first. The scanner and monitors are read-only. No cloud service is required; the only network call is the optional signature update.

## Look and feel

Settings > Appearance switches between System, Light and Dark. System follows the Windows app mode and changes with it. Navigation is the icon rail on the left; related pages share tabs (Scan: Malware scan and Processes; Network: Connections and Firewall; History: History and Reports; Settings: Appearance, Administrator and Updates).

## Administrator password

Open **Administrator** in the app to set a password. Once set, applying fixes, quarantine restore/delete, disk cleanup, installing updates, and pausing or quitting protection all ask for it first. A correct password unlocks those actions for a few minutes (default 10, adjustable), then they lock again, and repeated wrong guesses add a growing delay. Only a salted PBKDF2 hash is stored (`data\admin.json`). This protects the app itself; it is not a substitute for a Windows account password.

## Install
Download `AegisGuardSetup-<version>.exe` from the [Releases](https://github.com/pateldarshil8/AegisGuard/releases) page and run it.

- Windows shows an "unknown publisher" warning because the installer is not code-signed yet. Choose *More info -> Run anyway* only if you trust where you got it from.
- Installs to `C:\Program Files\AegisGuard`; reports, quarantine and settings live in `C:\ProgramData\AegisGuard`.
- Tick "Start AegisGuard protection when I sign in" for always-on protection.

## Updates

Installed copies check GitHub Releases for new versions. A popup appears when you open the app (and a notification plus the Updates tab if it is already running). Each download is verified against its published SHA-256 before it is installed, and installing an update asks for approval first.

## Command line
`aegisguard-cli` (installed) or `aegisguard` (from source):

```
full | scan [--mode quick|full|deep] [--path DIR] | procs | net [--watch N] | firewall | audit
fix | block <exe-or-ip> | unblock <rule> | rules
quarantine list|add|restore|delete | cleanup | space | history
update-signatures | monitor | ui
```

## Run from source
```
python -m venv .venv
.venv\Scripts\activate
pip install -e .[ui,dev]
aegisguard full
aegisguard ui
pytest
```
Building the installer: see [docs/BUILDING.md](docs/BUILDING.md). Threat feed setup: [docs/SIGNATURES.md](docs/SIGNATURES.md).

## Limits (be honest about them)
- Heuristics and hash matching only: no kernel driver, no real-time file hook, no sandboxing. New or custom malware can slip past.
- Some checks and all fixes need administrator rights.
- Unsigned build; antivirus products may occasionally flag a freshly built exe as a false positive.

## Author
Darshil Patel - [GitHub](https://github.com/pateldarshil8)
