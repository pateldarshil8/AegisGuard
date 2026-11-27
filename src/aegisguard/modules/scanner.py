"""File scanner: known-bad hashes plus explainable heuristics.

Every finding says *why* it was raised, so you can judge it. No file is touched by the scanner;
use the quarantine module to act on a result.
"""
from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Callable
from pathlib import Path

from ..core import config, settings
from ..core.models import Finding, ScanResult, Severity

# Known-bad SHA-256 hashes. The EICAR hash lets you verify detection safely.
# Add your own in data\threat_hashes.txt (one per line: "<sha256> <name>").
KNOWN_BAD = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR test file",
}
MAX_HASH_BYTES = 50 * 1024 * 1024
MAX_SCRIPT_BYTES = 1024 * 1024
DEEP_MAX_HASH_BYTES = 300 * 1024 * 1024

MODES = {
    "quick": "Quick scan",
    "full": "Full scan",
    "deep": "Deep scan",
    "custom": "Custom scan",
}

# Extensions people trust as "just a document/media file"
DOC_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".gif",
            ".txt", ".mp3", ".mp4"}
SCRIPT_EXTS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"}

SCRIPT_PATTERNS = {
    "encoded command": re.compile(r"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", re.I),
    "base64 decoding": re.compile(r"frombase64string", re.I),
    "remote download": re.compile(r"downloadstring|downloadfile|invoke-webrequest|net\.webclient", re.I),
    "invoke-expression": re.compile(r"\biex\b|invoke-expression", re.I),
    "certutil download": re.compile(r"certutil[^\n]*-urlcache", re.I),
    "bitsadmin transfer": re.compile(r"bitsadmin[^\n]*/transfer", re.I),
    "remote mshta": re.compile(r"mshta[^\n]*https?://", re.I),
    "hidden window": re.compile(r"-w(indowstyle)?\s+hidden", re.I),
}


def sha256(path: Path) -> str | None:
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def load_known_bad() -> dict[str, str]:
    """Hashes from the user-editable threat list."""
    p = config.DATA_DIR / "threat_hashes.txt"
    out: dict[str, str] = {}
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            digest, _, name = line.partition(" ")
            if re.fullmatch(r"[0-9a-fA-F]{64}", digest):
                out[digest.lower()] = name.strip() or "Listed threat"
    except OSError:
        pass
    try:  # downloaded feed (see signatures.py); your own entries above take precedence
        for line in (config.DATA_DIR / "threat_feed.txt").read_text(encoding="utf-8").splitlines():
            h = line.strip().lower()
            if re.fullmatch(r"[0-9a-f]{64}", h):
                out.setdefault(h, "Known malware (threat feed)")
    except OSError:
        pass
    return out


def _starts_with_mz(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False


def _script_hits(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return [name for name, rx in SCRIPT_PATTERNS.items() if rx.search(text)]


def scan_path(path: Path, res: ScanResult, deep: bool = False) -> None:
    try:
        size = path.stat().st_size
    except OSError:
        return
    ext = path.suffix.lower()
    suffixes = [s.lower() for s in path.suffixes]

    # invoice.pdf.exe style tricks
    if ext in config.RISKY_EXTENSIONS and len(suffixes) >= 2 and suffixes[-2] in DOC_EXTS:
        res.add(Finding("scanner", "Double-extension executable", Severity.HIGH, path.name,
                        "Likely disguised malware; quarantine or delete.", str(path)))

    # A real program renamed to look like a document or picture. A deep scan checks every file type, not just
    # the ones people trust as documents.
    if (ext in DOC_EXTS or (deep and ext not in config.RISKY_EXTENSIONS and ext not in {".sys", ".ocx", ".cpl", ".scr"}
                            and ext)) and size >= 2 and size <= MAX_HASH_BYTES and _starts_with_mz(path):
        res.add(Finding("scanner", f"Executable disguised as {ext} file", Severity.HIGH, path.name,
                        "File has a Windows program header but a document/media extension. Quarantine it.",
                        str(path)))

    # Scripts that combine download / obfuscation / execution tricks
    if ext in SCRIPT_EXTS and size <= MAX_SCRIPT_BYTES:
        hits = _script_hits(path)
        if hits:
            sev = Severity.HIGH if len(hits) >= 3 else Severity.MEDIUM if len(hits) == 2 else Severity.LOW
            res.add(Finding("scanner", "Suspicious script behavior", sev, ", ".join(hits),
                            "Read the script before running it; quarantine it if you don't recognise it.",
                            str(path)))

    # Known-bad hash
    limit = DEEP_MAX_HASH_BYTES if deep else MAX_HASH_BYTES
    if size <= limit and (ext in config.RISKY_EXTENSIONS or size < 1024 or (deep and ext in {".sys", ".ocx", ".cpl"})):
        digest = sha256(path)
        if digest in KNOWN_BAD:
            res.add(Finding("scanner", f"Known threat: {KNOWN_BAD[digest]}", Severity.CRITICAL,
                            digest, "Quarantine immediately.", str(path)))


def fixed_drives() -> list[Path]:
    """Every local (non-removable, non-network) drive; the home folder if the system can't list drives."""
    roots: list[Path] = []
    try:
        import psutil
        for part in psutil.disk_partitions(all=False):
            opts = part.opts.lower()
            if "cdrom" in opts or "removable" in opts or part.fstype.lower() in {"", "nfs", "cifs", "smbfs"}:
                continue
            roots.append(Path(part.mountpoint))
    except Exception:
        pass
    return roots or [Path.home()]


def targets(mode: str, custom: list[Path] | None = None) -> list[Path]:
    if mode == "custom":
        return list(custom or [])
    if mode in ("full", "deep"):
        return fixed_drives()
    return list(config.QUICK_SCAN_DIRS)


def _walk(root: Path, skip: tuple[str, ...], skip_names: set[str], mode: str):
    """Yield every file under root without following links, skipping excluded and bookkeeping folders."""
    if root.is_file():
        yield root
        return
    for cur, dirs, files in os.walk(root, followlinks=False, onerror=lambda e: None):
        here = cur.lower()
        if here.startswith(skip):
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d.lower() not in skip_names
                   and not (mode == "full" and os.path.join(cur, d).lower() in config.FULL_SCAN_SKIP_PATHS)
                   and not os.path.islink(os.path.join(cur, d))]
        for f in files:
            yield Path(cur, f)


def run(dirs: list[Path] | None = None, mode: str = "quick",
        progress: Callable[[int, str], None] | None = None,
        cancelled: Callable[[], bool] | None = None) -> ScanResult:
    """Scan folders and return findings. mode: quick | full | deep | custom (dirs given = custom).

    progress(count, current_path) is called regularly; cancelled() returning True stops the scan early.
    """
    res = ScanResult()
    KNOWN_BAD.update(load_known_bad())
    if dirs:
        mode = "custom" if mode == "quick" else mode
    roots = list(dirs) if dirs else targets(mode)
    skip = (str(config.QUARANTINE_DIR).lower(), *(e.lower() for e in settings.load().exclusions))
    skip_names = config.SCAN_SKIP_NAMES if mode in ("full", "deep") else set()
    deep = mode == "deep"
    count = 0
    stopped = False
    for d in roots:
        if stopped or not d.exists():
            continue
        try:
            for p in _walk(d, skip, skip_names, mode):
                if cancelled and cancelled():
                    stopped = True
                    break
                if str(p).lower().startswith(skip):
                    continue
                count += 1
                if progress and count % 200 == 0:
                    progress(count, str(p))
                scan_path(p, res, deep)
        except OSError:
            continue
    if progress:
        progress(count, "")
    res.meta["files_scanned"] = count
    res.meta["mode"] = mode
    res.meta["stopped"] = stopped
    return res
