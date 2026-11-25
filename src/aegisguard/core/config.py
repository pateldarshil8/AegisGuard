"""Paths and settings. Everything lives under the install root (default C:\\AegisGuard)."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(os.environ.get("AEGISGUARD_HOME", r"C:\AegisGuard"))
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
