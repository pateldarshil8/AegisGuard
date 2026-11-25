"""System health monitor: CPU, memory, disk, top processes."""
from __future__ import annotations

import psutil

from ..core import config
from ..core.models import Finding, ScanResult, Severity


def snapshot() -> dict:
    disks = {}
    for p in psutil.disk_partitions(all=False):
        try:
            disks[p.mountpoint] = psutil.disk_usage(p.mountpoint).percent
        except OSError:
            continue
    procs = sorted(
        (p.info for p in psutil.process_iter(["pid", "name", "memory_percent"])),
        key=lambda i: i.get("memory_percent") or 0,
        reverse=True,
    )[:5]
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "memory_percent": psutil.virtual_memory().percent,
        "disks": disks,
        "top_memory_processes": procs,
    }


def run() -> ScanResult:
    res = ScanResult()
    s = snapshot()
    res.meta["health"] = s
    if s["cpu_percent"] >= config.CPU_WARN:
        res.add(Finding("health", "High CPU usage", Severity.MEDIUM, f"{s['cpu_percent']}%",
                        "Check top processes; close or investigate heavy ones."))
    if s["memory_percent"] >= config.MEM_WARN:
        res.add(Finding("health", "High memory usage", Severity.MEDIUM, f"{s['memory_percent']}%",
                        "Close unused apps or review top memory processes."))
    for mount, pct in s["disks"].items():
        if pct >= config.DISK_WARN:
            res.add(Finding("health", f"Disk {mount} nearly full", Severity.HIGH, f"{pct}% used",
                            "Free space: clear temp files, uninstall unused apps."))
    return res
