"""Network monitor (read-only): flags risky listeners and suspicious outbound connections.

v0.2 uses simple, explainable rules. It never blocks anything; blocking will come later,
behind explicit user approval.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

import psutil

from ..core.models import Finding, ScanResult, Severity

# Ports that should rarely be reachable from outside the machine.
RISKY_LISTEN_PORTS = {
    21: "FTP", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB",
    3389: "RDP", 5900: "VNC", 5985: "WinRM",
}
SUSPICIOUS_PATH_MARKERS = ("\\temp\\", "\\downloads\\", "\\appdata\\local\\temp", "\\users\\public\\")
# Ports commonly abused by backdoors/C2 when used by user-writable-location programs.
UNUSUAL_OUTBOUND = {4444, 1337, 31337, 6667, 8888, 9001}


@dataclass
class Conn:
    pid: int | None
    proc: str
    exe: str
    status: str
    laddr_ip: str
    laddr_port: int
    raddr_ip: str | None
    raddr_port: int | None


def _is_public(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_unspecified)


def collect() -> list[Conn]:
    out: list[Conn] = []
    for c in psutil.net_connections(kind="inet"):
        proc = exe = ""
        if c.pid:
            try:
                p = psutil.Process(c.pid)
                proc, exe = p.name(), p.exe()
            except (psutil.Error, OSError):
                pass
        out.append(Conn(c.pid, proc, exe, c.status, c.laddr.ip if c.laddr else "",
                        c.laddr.port if c.laddr else 0,
                        c.raddr.ip if c.raddr else None, c.raddr.port if c.raddr else None))
    return out


def analyze(conns: list[Conn]) -> ScanResult:
    res = ScanResult()
    res.meta["connections_seen"] = len(conns)
    seen: set[tuple] = set()

    def add(key, title, sev, detail, fix, path=None):
        if key in seen:
            return
        seen.add(key)
        res.add(Finding("netmon", title, sev, detail, fix, path))

    for c in conns:
        who = f"{c.proc or 'unknown'} (pid {c.pid})"
        exposed = c.laddr_ip in ("0.0.0.0", "::", "")
        if c.status == "LISTEN" and exposed and c.laddr_port in RISKY_LISTEN_PORTS:
            svc = RISKY_LISTEN_PORTS[c.laddr_port]
            add(("listen", c.laddr_port), f"{svc} port {c.laddr_port} open to all interfaces", Severity.MEDIUM,
                who, "Disable the service or block the port in Windows Firewall if you don't need it.", c.exe or None)
        low = c.exe.lower()
        from_risky_path = any(m in low for m in SUSPICIOUS_PATH_MARKERS)
        if c.status == "ESTABLISHED" and _is_public(c.raddr_ip):
            if from_risky_path:
                add(("path", c.exe), "Program from a temp/download folder is talking to the internet", Severity.HIGH,
                    f"{who} -> {c.raddr_ip}:{c.raddr_port}",
                    "Verify the program; if unknown, end it and scan the file.", c.exe)
            if c.raddr_port in UNUSUAL_OUTBOUND:
                add(("port", c.pid, c.raddr_port), f"Outbound connection to unusual port {c.raddr_port}", Severity.MEDIUM,
                    f"{who} -> {c.raddr_ip}", "Investigate this process.", c.exe or None)
    return res


def run() -> ScanResult:
    try:
        return analyze(collect())
    except (psutil.AccessDenied, PermissionError):
        res = ScanResult()
        res.add(Finding("netmon", "Need administrator rights for full connection list", Severity.LOW,
                        "", "Re-run from an elevated terminal."))
        return res
