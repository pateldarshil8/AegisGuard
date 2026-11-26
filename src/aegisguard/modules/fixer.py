"""Vulnerability / misconfiguration checks with approval-gated fixes.

Design rules:
  * Checks are read-only.
  * A fix is only a *proposal* (Fix) until the user explicitly approves it.
  * Nothing here runs a fix on its own; apply() is called by the CLI/UI after consent.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import Callable

from ..core import proc
from ..core.models import Finding, ScanResult, Severity
from . import firewall

try:  # Windows only
    import winreg
except ImportError:  # pragma: no cover - lets tests run elsewhere
    winreg = None  # type: ignore[assignment]

SUSPICIOUS_PATH_MARKERS = ("\\temp\\", "\\downloads\\", "\\appdata\\local\\temp", "\\users\\public\\")


@dataclass
class Fix:
    finding: Finding
    description: str
    command: list[str]
    needs_admin: bool = True
    extra_commands: list[list[str]] = field(default_factory=list)


RegReader = Callable[[str, str], object | None]  # (key path under HKLM, value name) -> value


def _hklm_reader(path: str, name: str):
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def _run_keys() -> dict[str, str]:
    """Startup entries from the standard Run keys (HKLM + HKCU)."""
    out: dict[str, str] = {}
    if winreg is None:
        return out
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        try:
            with winreg.OpenKey(hive, r"Software\Microsoft\Windows\CurrentVersion\Run") as k:
                i = 0
                while True:
                    try:
                        n, v, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    out[n] = str(v)
                    i += 1
        except OSError:
            continue
    return out


def _defender_realtime_on() -> bool | None:
    try:
        r = proc.run(
            ["powershell", "-NoProfile", "-Command", "(Get-MpComputerStatus).RealTimeProtectionEnabled"],
            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    txt = r.stdout.strip().lower()
    return True if txt == "true" else False if txt == "false" else None


def propose(reg: RegReader = _hklm_reader, run_entries: dict[str, str] | None = None,
            defender_on: bool | None = ..., fw_states: dict[str, str] | None = ...,  # type: ignore[assignment]
            ) -> tuple[ScanResult, list[Fix]]:
    res, fixes = ScanResult(), []

    def add(title, sev, detail, remediation, cmd=None, admin=True):
        f = Finding("fixer", title, sev, detail, remediation)
        res.add(f)
        if cmd:
            fixes.append(Fix(f, remediation, cmd, admin))

    # UAC disabled
    if reg(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA") == 0:
        add("User Account Control (UAC) is disabled", Severity.HIGH, "EnableLUA = 0",
            "Enable UAC (requires reboot).",
            ["reg", "add", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
             "/v", "EnableLUA", "/t", "REG_DWORD", "/d", "1", "/f"])

    # SMBv1 explicitly enabled
    if reg(r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1") == 1:
        add("SMBv1 is enabled", Severity.HIGH, "Legacy protocol exploited by WannaCry-class attacks",
            "Disable SMBv1 server.",
            ["powershell", "-NoProfile", "-Command", "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"])

    # RDP enabled (inbound remote desktop)
    if reg(r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections") == 0:
        add("Remote Desktop is enabled", Severity.MEDIUM, "Inbound RDP accepted",
            "Disable Remote Desktop if you don't use it.",
            ["reg", "add", r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
             "/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "1", "/f"])

    # Defender real-time protection
    d = _defender_realtime_on() if defender_on is ... else defender_on
    if d is False:
        add("Defender real-time protection is OFF", Severity.HIGH, "",
            "Turn real-time protection back on.",
            ["powershell", "-NoProfile", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $false"])

    # Firewall profiles switched off
    states = (firewall.profile_states() or {}) if fw_states is ... else (fw_states or {})
    for pname, state in states.items():
        if state.upper() != "ON":
            add(f"{pname} firewall profile is OFF", Severity.HIGH, f"State: {state}",
                f"Turn the {pname} firewall profile back on.",
                ["netsh", "advfirewall", "set", f"{pname.lower()}profile", "state", "on"])

    # Startup entries launching from user-writable/temp locations (report only: removal is a judgment call)
    for name, cmdline in (run_entries if run_entries is not None else _run_keys()).items():
        low = cmdline.lower()
        if any(m in low for m in SUSPICIOUS_PATH_MARKERS):
            add(f"Suspicious startup entry: {name}", Severity.MEDIUM, cmdline,
                "Review this entry; remove it from Settings > Apps > Startup if you don't recognise it.")
    return res, fixes


def apply(fix: Fix, approved: bool) -> tuple[bool, str]:
    """Run a fix (all of its commands) only if the user approved it. Stops at the first failure."""
    if not approved:
        return False, "skipped (not approved)"
    outputs: list[str] = []
    for cmd in [fix.command, *fix.extra_commands]:
        try:
            r = proc.run(cmd, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as e:
            return False, str(e)
        out = (r.stdout or r.stderr).strip()
        if r.returncode != 0:
            return False, out or f"exit {r.returncode}"
        if out:
            outputs.append(out)
    return True, "; ".join(outputs) or "ok"


def run() -> ScanResult:
    return propose()[0]
