"""Firewall audit (v0.1 read-only). Smart rule management comes later, behind explicit user approval."""
from __future__ import annotations

import re
import subprocess

from ..core.models import Finding, ScanResult, Severity


def _netsh_profiles() -> str:
    out = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"],
                         capture_output=True, text=True, timeout=20)
    return out.stdout


def run() -> ScanResult:
    res = ScanResult()
    try:
        text = _netsh_profiles()
    except (OSError, subprocess.SubprocessError) as e:
        res.add(Finding("firewall", "Could not query firewall", Severity.LOW, str(e)))
        return res
    # Parse "<Name> Profile Settings:" blocks followed by "State  ON/OFF"
    for name, state in re.findall(r"(\w+) Profile Settings:.*?State\s+(\w+)", text, flags=re.S):
        res.meta[f"firewall_{name.lower()}"] = state
        if state.upper() != "ON":
            res.add(Finding("firewall", f"{name} firewall profile is OFF", Severity.HIGH,
                            f"State: {state}", f"Enable: netsh advfirewall set {name.lower()}profile state on"))
    return res
