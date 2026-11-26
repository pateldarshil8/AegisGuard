"""Disk space helpers.

  * scan_cleanup(): finds safe-to-remove files (temp files, crash dumps, web cache) older than a few days
  * clean():        deletes exactly those files, only when approved, only inside the known cleanup folders
  * largest_items(): shows which folders use the most space (read-only)

Only files are removed (never folders), symlinks/junctions are never followed, and the folders are limited to
the allow-list in targets(). Your Downloads, Documents and everything else are never touched.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

MAX_CANDIDATES = 200_000


@dataclass
class Candidate:
    path: str
    size: int
    category: str


def targets() -> dict[str, list[Path]]:
    env = os.environ
    out: dict[str, list[Path]] = {}
    if env.get("TEMP"):
        out["User temp files"] = [Path(env["TEMP"])]
    out["Windows temp files"] = [Path(env.get("SystemRoot", r"C:\Windows")) / "Temp"]
    local = env.get("LOCALAPPDATA")
    if local:
        out["Crash dumps"] = [Path(local) / "CrashDumps"]
        out["Web cache"] = [Path(local) / "Microsoft" / "Windows" / "INetCache"]
    return out


def _is_link(e: os.DirEntry) -> bool:
    return e.is_symlink() or getattr(e, "is_junction", lambda: False)()


def _walk_files(root: Path) -> Iterator[tuple[Path, os.stat_result]]:
    stack = [root]
    while stack:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    try:
                        if _is_link(e):
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(Path(e.path))
                        elif e.is_file(follow_symlinks=False):
                            yield Path(e.path), e.stat(follow_symlinks=False)
                    except OSError:
                        continue
        except OSError:
            continue


def scan_cleanup(tgts: dict[str, list[Path]] | None = None, min_age_days: float = 2,
                 now: Callable[[], float] = time.time) -> list[Candidate]:
    """Files older than min_age_days (recently used files are likely still in use)."""
    cutoff, out = now() - min_age_days * 86400, []
    for category, roots in (tgts if tgts is not None else targets()).items():
        for root in roots:
            for p, st in _walk_files(root):
                if st.st_mtime <= cutoff:
                    out.append(Candidate(str(p), st.st_size, category))
                    if len(out) >= MAX_CANDIDATES:
                        return out
    return out


def summarize(cands: list[Candidate]) -> dict[str, tuple[int, int]]:
    """{category: (file_count, total_bytes)}"""
    out: dict[str, tuple[int, int]] = {}
    for c in cands:
        n, b = out.get(c.category, (0, 0))
        out[c.category] = (n + 1, b + c.size)
    return out


def clean(cands: list[Candidate], approved: bool,
          tgts: dict[str, list[Path]] | None = None) -> tuple[int, int, int]:
    """Delete approved candidates. Returns (bytes_freed, files_deleted, files_skipped_or_failed)."""
    if not approved:
        return 0, 0, 0
    roots = [r.resolve() for rs in (tgts if tgts is not None else targets()).values() for r in rs]
    freed = deleted = failed = 0
    for c in cands:
        p = Path(c.path)
        try:
            if p.is_symlink() or not p.is_file():
                failed += 1
                continue
            rp = p.resolve()
            if not any(r in rp.parents for r in roots):  # never delete outside the allow-listed folders
                failed += 1
                continue
            size = p.stat().st_size
            os.remove(p)
            freed += size
            deleted += 1
        except OSError:
            failed += 1  # in use or protected: leave it
    return freed, deleted, failed


def _dir_size(path: Path, deadline: float, clock: Callable[[], float]) -> tuple[int, bool]:
    total, complete = 0, True
    for _, st in _walk_files(path):
        total += st.st_size
        if clock() > deadline:
            return total, False
    return total, complete


def largest_items(root: Path, top: int = 15, max_seconds: float = 45.0,
                  clock: Callable[[], float] = time.monotonic,
                  workers: int = 8) -> tuple[list[tuple[str, int]], bool]:
    """Biggest entries directly under root. Returns ([(path, bytes)], complete).

    Folders are measured in parallel so one huge folder (e.g. AppData) can't starve the rest. If the time budget
    runs out, folders still being measured report what they have so far and complete is False.
    """
    from concurrent.futures import ThreadPoolExecutor

    deadline = clock() + max_seconds
    try:
        entries = list(os.scandir(root))
    except OSError:
        return [], True

    def measure(e: os.DirEntry) -> tuple[str, int, bool] | None:
        try:
            if _is_link(e):
                return None
            if e.is_file(follow_symlinks=False):
                return e.path, e.stat(follow_symlinks=False).st_size, True
            if e.is_dir(follow_symlinks=False):
                if clock() > deadline:
                    return e.path, 0, False
                size, done = _dir_size(Path(e.path), deadline, clock)
                return e.path, size, done
        except OSError:
            return None
        return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = [r for r in pool.map(measure, entries) if r]
    complete = all(done for _, _, done in results)
    results.sort(key=lambda r: r[1], reverse=True)
    return [(p, size) for p, size, _ in results[:top]], complete


def human(n: int) -> str:
    x = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if x < 1024 or unit == "TB":
            return f"{x:.0f} {unit}" if unit == "B" else f"{x:.1f} {unit}"
        x /= 1024
    return f"{n} B"
