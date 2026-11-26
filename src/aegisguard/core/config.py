"""Paths and settings. Everything lives under the install root (default C:\\AegisGuard)."""
from __future__ import annotations

import os
import sys
from pathlib import Path


def _default_root() -> Path:
    # Installed (PyInstaller) build: Program Files is read-only for normal users, so data goes in ProgramData.
    if getattr(sys, "frozen", False):
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "AegisGuard"
    return Path(r"C:\AegisGuard")  # development checkout


ROOT = Path(os.environ.get("AEGISGUARD_HOME") or _default_root())
DATA_DIR = ROOT / "data"
REPORTS_DIR = DATA_DIR / "reports"
QUARANTINE_DIR = DATA_DIR / "quarantine"
LOG_FILE = DATA_DIR / "aegisguard.log"

# Health thresholds (percent)
CPU_WARN, MEM_WARN, DISK_WARN = 85.0, 85.0, 90.0

# Folders the quick scan covers
QUICK_SCAN_DIRS = [
    Path(os.environ.get("USERPROFILE", "C:\\Users\\Public")) / "Downloads",
    Path(os.environ.get("TEMP", "C:\\Windows\\Temp")),
]

# Extensions that are risky when found in user-writable locations
RISKY_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".dll", ".lnk"}


def ensure_dirs() -> None:
    for d in (DATA_DIR, REPORTS_DIR, QUARANTINE_DIR):
        d.mkdir(parents=True, exist_ok=True)
