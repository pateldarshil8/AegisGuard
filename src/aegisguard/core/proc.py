"""Run helper programs (netsh, powershell, reg) without flashing a console window.

A program built without a console (our GUI) makes Windows open a new console window for every child process unless
CREATE_NO_WINDOW is set. Use proc.run() instead of subprocess.run().
"""
from __future__ import annotations

import subprocess
import sys

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0


def run(cmd, **kwargs) -> subprocess.CompletedProcess:
    if NO_WINDOW:
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | NO_WINDOW
    return subprocess.run(cmd, **kwargs)
