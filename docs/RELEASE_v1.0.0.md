# AegisGuard v1.0.0 - first release

Windows endpoint security and system health suite. Desktop app + command-line tool.

**Download:** `AegisGuardSetup-1.0.0.exe` (attached below). Windows 10/11, 64-bit.

## Highlights
- Malware scan with heuristics (disguised executables, suspicious scripts) and known-bad hashes; quarantine with restore
- Running-process and network checks; block a program or IP in Windows Firewall after you approve it
- Detects risky settings (UAC, SMBv1, RDP, Defender/firewall off) and offers reviewed one-click fixes
- Background protection with tray alerts, start-at-sign-in option
- Disk cleanup and a "where is my space going" report
- Security score, trend and change history
- Optional threat-hash feed updates (free abuse.ch key)

## Good to know
- Not code-signed yet: Windows SmartScreen will show an "unknown publisher" warning.
- Complements, does not replace, Windows Defender.
- Some checks and all fixes need administrator rights.

## Install
Run the installer, tick "Start AegisGuard protection when I sign in" if you want always-on protection.
Uninstall from Settings -> Apps; the uninstaller asks whether to delete your data.

## Verify your download
SHA-256 of the installer: *(paste output of `Get-FileHash .\AegisGuardSetup-1.0.0.exe`)*
