"""File scanner (v0.1: hashing + heuristics; signature/ML engines plug in later)."""
from __future__ import annotations

import hashlib
from pathlib import Path

from ..core import config
from ..core.models import Finding, ScanResult, Severity

# Known-bad SHA-256 hashes (populate from a threat-intel feed later).
# The EICAR test file hash lets you verify detection safely.
KNOWN_BAD = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR test file",
}
MAX_HASH_BYTES = 50 * 1024 * 1024


def sha256(path: Path) -> str | None:
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def scan_path(path: Path, res: ScanResult) -> None:
    try:
        size = path.stat().st_size
    except OSError:
        return
    ext = path.suffix.lower()
    # Double extension trick, e.g. invoice.pdf.exe
    if ext in config.RISKY_EXTENSIONS and len(path.suffixes) >= 2 and path.suffixes[-2].lower() in {".pdf", ".doc", ".docx", ".jpg", ".png", ".txt", ".xlsx"}:
        res.add(Finding("scanner", "Double-extension executable", Severity.HIGH, path.name,
                        "Likely disguised malware; quarantine or delete.", str(path)))
    if size <= MAX_HASH_BYTES and (ext in config.RISKY_EXTENSIONS or size < 1024):
        digest = sha256(path)
        if digest in KNOWN_BAD:
            res.add(Finding("scanner", f"Known threat: {KNOWN_BAD[digest]}", Severity.CRITICAL,
                            digest, "Quarantine immediately.", str(path)))


def run(dirs: list[Path] | None = None) -> ScanResult:
    res = ScanResult()
    count = 0
    for d in dirs or config.QUICK_SCAN_DIRS:
        if not d.exists():
            continue
        for p in d.rglob("*"):
            if p.is_file():
                count += 1
                scan_path(p, res)
    res.meta["files_scanned"] = count
    return res
