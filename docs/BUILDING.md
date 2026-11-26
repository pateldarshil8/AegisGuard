# Building the AegisGuard installer

## One-time setup
1. Python 3.10+ and the project venv (`pip install -e .[ui,dev,build]`).
2. Inno Setup 6 (free): `winget install JRSoftware.InnoSetup`

## Build
```
.\installer\build.ps1                 # portable folder + AegisGuardSetup-<version>.exe
.\installer\build.ps1 -SkipInstaller  # just dist\AegisGuard\ (no Inno Setup needed)
```
Outputs:
- `dist\AegisGuard\AegisGuard.exe` - desktop app (no console)
- `dist\AegisGuard\aegisguard-cli.exe` - command-line tool
- `dist-installer\AegisGuardSetup-<version>.exe` - the installer you hand to people

## What the installer does
- Installs to `C:\Program Files\AegisGuard` (needs administrator rights).
- Start Menu shortcut, optional desktop shortcut.
- Optional "start when I sign in": a scheduled task that launches `AegisGuard.exe --minimized` (tray only) with the
  user's highest available rights, so network/firewall checks see everything without a UAC prompt each login.
- Creates `C:\ProgramData\AegisGuard` for reports, quarantine, settings and logs.
- Uninstaller stops the app, removes the sign-in task, and asks whether to delete the data folder.

## Test it before sharing
Use a throwaway Windows VM (or Windows Sandbox): install, open the app, check the tray icon, run a full check,
sign out/in to confirm start-at-sign-in, then uninstall and confirm everything is removed.

## Known limits (v0.1)
- **SmartScreen:** an unsigned installer shows "Windows protected your PC / unknown publisher". Fix: sign the
  installer and exes with a code-signing certificate (set `AEGISGUARD_SIGN_PFX` and `AEGISGUARD_SIGN_PASSWORD`;
  `build.ps1` signs automatically if `signtool.exe` is on PATH). A standard certificate builds reputation over time;
  an EV certificate removes the warning immediately.
- **Antivirus false positives:** PyInstaller programs are sometimes flagged. The folder build used here triggers
  this far less than one-file builds. If Defender flags a build, submit it at
  https://www.microsoft.com/wdsi/filesubmission as a false positive.
- Data is shared by all users of the PC (`C:\ProgramData`), not per-user.
