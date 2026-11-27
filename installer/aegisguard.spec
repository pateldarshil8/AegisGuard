# -*- mode: python ; coding: utf-8 -*-
# Builds one folder (dist\AegisGuard) holding two programs that share their libraries:
#   AegisGuard.exe       - the desktop app (no console window)
#   aegisguard-cli.exe   - the command-line tool (console), without the Qt libraries
# A folder build (not one-file) starts faster and trips antivirus false positives far less often.
from pathlib import Path

spec_dir = Path(SPECPATH)
src = str(spec_dir.parent / "src")
icon_file = spec_dir / "aegisguard.ico"
icon = str(icon_file) if icon_file.exists() else None

a_gui = Analysis([str(spec_dir / "entry_gui.py")], pathex=[src], hiddenimports=["PySide6.QtSvg"], excludes=["tkinter", "pytest"])
a_cli = Analysis([str(spec_dir / "entry_cli.py")], pathex=[src],
                 excludes=["tkinter", "pytest", "PySide6", "shiboken6", "aegisguard.ui"])

MERGE((a_gui, "AegisGuard", "AegisGuard"), (a_cli, "aegisguard-cli", "aegisguard-cli"))

pyz_gui = PYZ(a_gui.pure)
exe_gui = EXE(pyz_gui, a_gui.scripts, [], exclude_binaries=True, name="AegisGuard",
              console=False, icon=icon, upx=False)

pyz_cli = PYZ(a_cli.pure)
exe_cli = EXE(pyz_cli, a_cli.scripts, [], exclude_binaries=True, name="aegisguard-cli",
              console=True, icon=icon, upx=False)

coll = COLLECT(exe_gui, a_gui.binaries, a_gui.datas,
               exe_cli, a_cli.binaries, a_cli.datas,
               strip=False, upx=False, name="AegisGuard")
