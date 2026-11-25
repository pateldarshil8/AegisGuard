"""Background protection: watches your folders and re-runs checks on a schedule, raising alerts for new findings.

  * files:     new/changed files in the watched folders are scanned as they appear
  * processes: running processes are re-checked every minute
  * network:   connections and listeners are re-checked every minute
  * audit:     scan + settings + firewall + health, hourly

Alerts are de-duplicated (you hear about each issue once), filtered by minimum severity, and appended to
data\\alerts.log. The monitor only observes and reports; it never changes anything by itself.
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from ..core import config, settings as settings_mod
from ..core.models import Finding, ScanResult
from . import firewall, fixer, health, netmon, processes, reports, scanner

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SKIP_EXT = {".crdownload", ".part", ".partial", ".tmp", ".download"}  # downloads still in progress


class FileWatcher:
    """Polls folders and scans files that are new or changed since the last poll."""

    def __init__(self, dirs: list[str], exclusions: list[str] | None = None, max_depth: int = 3,
                 now: Callable[[], float] = time.time, settle_seconds: float = 1.0):
        self.dirs = [Path(d) for d in dirs]
        self.exclusions = tuple(e.lower() for e in (exclusions or []))
        self.max_depth, self.now, self.settle = max_depth, now, settle_seconds
        self.state: dict[str, int] = {}
        self.baselined = False

    def _files(self, root: Path, depth: int = 0):
        try:
            with os.scandir(root) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir():
                            if depth < self.max_depth:
                                yield from self._files(Path(e.path), depth + 1)
                        elif e.is_file():
                            yield Path(e.path), e.stat().st_mtime_ns
                    except OSError:
                        continue
        except OSError:
            return

    def poll(self) -> ScanResult:
        res = ScanResult()
        for d in self.dirs:
            for p, mtime in self._files(d):
                key = str(p)
                if key.lower().startswith(self.exclusions) or p.suffix.lower() in SKIP_EXT:
                    continue
                if not self.baselined:  # first pass just records what already exists
                    self.state[key] = mtime
                    continue
                if self.state.get(key) == mtime:
                    continue
                if self.now() - mtime / 1e9 < self.settle:  # still being written; look again next poll
                    continue
                self.state[key] = mtime
                scanner.scan_path(p, res)
        self.baselined = True
        return res


@dataclass
class Task:
    name: str
    interval: float
    fn: Callable[[], ScanResult]
    last: float = float("-inf")


def default_tasks(s: settings_mod.Settings) -> list[Task]:
    watcher = FileWatcher(s.watch_dirs, s.exclusions)
    return [
        Task("files", s.file_poll_seconds, watcher.poll),
        Task("processes", s.process_seconds, processes.run),
        Task("network", s.network_seconds, netmon.run),
        Task("audit", s.audit_minutes * 60,
             lambda: reports.merge([scanner.run(), fixer.run(), firewall.run(), health.run()])),
    ]


class Monitor:
    def __init__(self, s: settings_mod.Settings | None = None, on_alert: Callable[[Finding], None] | None = None,
                 tasks: list[Task] | None = None, clock: Callable[[], float] = time.monotonic):
        self.settings = s or settings_mod.load()
        self.on_alert, self.clock = on_alert, clock
        self.tasks = tasks if tasks is not None else default_tasks(self.settings)
        self.min_rank = SEVERITY_RANK.get(self.settings.min_alert_severity, 2)
        self.seen: set[tuple] = set()
        self.errors: list[str] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def tick(self) -> list[Finding]:
        """Run every task that is due; return the findings that are new and severe enough to alert on."""
        now, new = self.clock(), []
        for t in self.tasks:
            if now - t.last < t.interval:
                continue
            t.last = now
            try:
                res = t.fn()
            except Exception as e:  # one failing check must not stop protection
                self.errors.append(f"{t.name}: {type(e).__name__}: {e}")
                continue
            for f in res.findings:
                key = (f.module, f.title, f.detail, f.path)
                if SEVERITY_RANK[f.severity.value] < self.min_rank or key in self.seen:
                    continue
                self.seen.add(key)
                new.append(f)
                self._log(f)
                if self.on_alert:
                    self.on_alert(f)
        return new

    @staticmethod
    def _log(f: Finding) -> None:
        try:
            config.DATA_DIR.mkdir(parents=True, exist_ok=True)
            with (config.DATA_DIR / "alerts.log").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"time": datetime.now().isoformat(timespec="seconds"), **f.to_dict()}) + "\n")
        except OSError:
            pass

    def run_forever(self) -> None:
        while not self._stop.is_set():
            self.tick()
            self._stop.wait(1.0)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self.run_forever, name="aegisguard-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())
