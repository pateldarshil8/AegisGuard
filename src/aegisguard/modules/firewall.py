"""Firewall audit (read-only). Rule changes live in fwrules/fixer and always need user approval."""
from __future__ import annotations

import re
import subprocess

from ..core.models import Finding, ScanResult, Severity


def profile_states() -> dict[str, str] | None:
    """{'Domain': 'ON', 'Private': 'ON', 'Public': 'ON'}, or None if netsh can't be queried."""
    try:
        out = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"],
                             capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    states = {n: s for n, s in re.findall(r"(\w+) Profile Settings:.*?State\s+(\w+)", out, flags=re.S)}
    return states or None


def run() -> ScanResult:
    res = ScanResult()
    states = profile_states()
    if states is None:
        res.add(Finding("firewall", "Could not query firewall", Severity.LOW,
                        "netsh unavailable or returned nothing", "Run from Windows, ideally as administrator."))
        return res
    for name, state in states.items():
        res.meta[f"firewall_{name.lower()}"] = state
        if state.upper() != "ON":
            res.add(Finding("firewall", f"{name} firewall profile is OFF", Severity.HIGH, f"State: {state}",
                            f"Enable: netsh advfirewall set {name.lower()}profile state on"))
    return res
