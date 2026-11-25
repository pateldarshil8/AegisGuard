"""Running-process scanner (read-only).

Looks for the classic signs of malware hiding in plain sight:
  * Windows system process names running from the wrong folder (masquerading)
  * look-alike names (svch0st.exe, scvhost.exe)
  * programs running from Temp/Downloads
  * PowerShell with encoded / download-and-execute command lines
"""
from __future__ import annotations

import os
from dataclasses import dataclass

import psutil

from ..core.models import Finding, ScanResult, Severity

SUSPICIOUS_PATH_MARKERS = ("\\temp\\", "\\downloads\\", "\\appdata\\local\\temp", "\\users\\public\\")
# Always live under %SystemRoot%\System32 (or SysWOW64)
SYSTEM_PROCESSES = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe",
                    "wininit.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe"}
WINDOWS_DIR_PROCESSES = {"explorer.exe"}
POWERSHELL = {"powershell.exe", "pwsh.exe"}
PS_MARKERS = ("-encodedcommand", "-enc ", "frombase64string", "downloadstring", "invoke-expression", " iex ",
              "-windowstyle hidden", "-w hidden")


@dataclass
class Proc:
    pid: int
    name: str
    exe: str
    cmdline: str = ""


def edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def collect() -> list[Proc]:
    out = []
    for p in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        i = p.info
        out.append(Proc(i["pid"], (i.get("name") or ""), (i.get("exe") or ""), " ".join(i.get("cmdline") or [])))
    return out


def analyze(procs: list[Proc], windir: str | None = None) -> ScanResult:
    windir = (windir or os.environ.get("SystemRoot", r"C:\Windows")).lower().rstrip("\\") + "\\"
    res = ScanResult()
    res.meta["processes_seen"] = len(procs)
    seen: set[tuple] = set()

    def add(title, sev, detail, fix, p: Proc):
        key = (title, p.name.lower(), p.exe.lower())
        if key in seen:
            return
        seen.add(key)
        res.add(Finding("processes", title, sev, detail, fix, p.exe or None))

    for p in procs:
        name, exe, low = p.name.lower(), p.exe, p.exe.lower()
        who = f"{p.name} (pid {p.pid})"
        if name in SYSTEM_PROCESSES | WINDOWS_DIR_PROCESSES:
            if exe and not low.startswith(windir):
                add(f"{p.name} running from an unexpected location", Severity.HIGH, f"{who}: {exe}",
                    "Real Windows processes run from the Windows folder. Likely masquerading malware: investigate.", p)
        elif name.endswith(".exe") and any(0 < edit_distance(name, s) <= 1 for s in SYSTEM_PROCESSES):
            add(f"Look-alike of a Windows process name: {p.name}", Severity.HIGH, f"{who}: {exe}",
                "Name differs from a core Windows process by one character. Investigate.", p)
        if exe and any(m in low for m in SUSPICIOUS_PATH_MARKERS):
            add("Program running from a temp/download folder", Severity.MEDIUM, f"{who}: {exe}",
                "Installers are normal here; unknown programs are not. Verify it.", p)
        if name in POWERSHELL:
            cl = p.cmdline.lower() + " "
            hits = [m.strip() for m in PS_MARKERS if m in cl]
            if hits:
                sev = Severity.HIGH if len(hits) >= 2 else Severity.MEDIUM
                add("PowerShell with suspicious command line", sev, f"{who}: {', '.join(hits)}",
                    "Encoded or download-and-run PowerShell is a common attack technique. Review the command.", p)
    return res


def run() -> ScanResult:
    return analyze(collect())
