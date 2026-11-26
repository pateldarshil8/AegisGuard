"""In-app updates from GitHub Releases.

Flow: check the latest release -> (user approves) -> download installer -> verify SHA-256 against the checksum
published in the same release -> run the installer silently (Windows asks for administrator permission).

Safety rules:
  * HTTPS and GitHub hosts only (including after redirects)
  * an installer with no published checksum is never offered
  * download size is capped; a checksum mismatch deletes the download
  * the file is re-hashed immediately before it is launched
  * nothing is installed without the user clicking Install
Note: updates are as trustworthy as your GitHub account and repository. Code-signing the installer would add a
second layer (Windows would then show your publisher name).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from .. import __version__
from ..core import config

REPO = "pateldarshil8/AegisGuard"
API_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
INSTALLER_RE = re.compile(r"^AegisGuardSetup-\d+(\.\d+)*\.exe$")
HEX64 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
MAX_INSTALLER_BYTES = 300 * 1024 * 1024
UA = {"User-Agent": f"AegisGuard/{__version__}"}


class UpdateError(Exception):
    pass


@dataclass
class UpdateInfo:
    version: str
    installer_url: str
    installer_name: str
    checksum_url: str
    notes: str
    page_url: str
    size: int


@dataclass
class Downloaded:
    path: Path
    sha256: str
    version: str


def parse_version(v: str) -> tuple[int, ...]:
    m = re.fullmatch(r"v?(\d+(?:\.\d+)*)", (v or "").strip())
    return tuple(int(x) for x in m.group(1).split(".")) if m else ()


def is_newer(latest: str, current: str) -> bool:
    a, b = parse_version(latest), parse_version(current)
    return bool(a) and a > b


def _host_ok(url: str) -> bool:
    u = urlparse(url or "")
    host = u.hostname or ""
    return u.scheme == "https" and (host == "github.com" or host.endswith(".githubusercontent.com"))


def enabled() -> bool:
    """Automatic checks run in the installed app (or when AEGISGUARD_UPDATES=1 for testing from source)."""
    from ..core import settings
    return (bool(getattr(sys, "frozen", False)) or os.environ.get("AEGISGUARD_UPDATES") == "1") \
        and settings.load().check_updates


def _http_json(url: str, opener: Callable = urllib.request.urlopen) -> dict:
    req = urllib.request.Request(url, headers={**UA, "Accept": "application/vnd.github+json"})
    try:
        with opener(req, timeout=15) as r:
            return json.loads(r.read(2_000_000).decode("utf-8", errors="ignore"))
    except urllib.error.HTTPError as e:
        if e.code == 404:  # no release published yet
            return {}
        raise UpdateError(f"Could not check for updates: {e}") from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise UpdateError(f"Could not check for updates: {e}") from None


def check(current: str = __version__, fetch_json: Callable[[str], dict] | None = None) -> UpdateInfo | None:
    """The newer release, or None if you're up to date (or the release can't be verified)."""
    data = (fetch_json or _http_json)(API_URL)
    tag = data.get("tag_name") or ""
    if not is_newer(tag, current):
        return None
    assets = {a.get("name"): a for a in data.get("assets", []) if isinstance(a, dict) and a.get("name")}
    inst = next((a for n, a in assets.items() if INSTALLER_RE.match(n)), None)
    if not inst:
        return None
    sums = assets.get(inst["name"] + ".sha256")
    if not sums:
        return None  # refuse anything we can't verify
    urls = (inst.get("browser_download_url", ""), sums.get("browser_download_url", ""))
    if not all(_host_ok(u) for u in urls):
        return None
    return UpdateInfo(tag.lstrip("v"), urls[0], inst["name"], urls[1], data.get("body") or "",
                      data.get("html_url") or "", int(inst.get("size") or 0))


def _expected_hash(info: UpdateInfo, opener: Callable) -> str:
    try:
        with opener(urllib.request.Request(info.checksum_url, headers=UA), timeout=30) as r:
            if not _host_ok(r.geturl()):
                raise UpdateError("Checksum download redirected to an unexpected host.")
            text = r.read(4096).decode("utf-8", errors="ignore")
    except (urllib.error.URLError, OSError) as e:
        raise UpdateError(f"Could not download the checksum: {e}") from None
    m = HEX64.search(text)
    if not m:
        raise UpdateError("The release's checksum file is not valid.")
    return m.group(0).lower()


def download(info: UpdateInfo, progress: Callable[[int, int], None] | None = None,
             opener: Callable = urllib.request.urlopen, dest_dir: Path | None = None) -> Downloaded:
    expected = _expected_hash(info, opener)
    dest = Path(dest_dir) if dest_dir else Path(tempfile.mkdtemp(prefix="aegisguard-update-"))  # user-private temp
    target = dest / info.installer_name
    part = target.with_name(target.name + ".part")
    h, total = hashlib.sha256(), 0
    try:
        with opener(urllib.request.Request(info.installer_url, headers=UA), timeout=60) as r, part.open("wb") as f:
            if not _host_ok(r.geturl()):
                raise UpdateError("Download redirected to an unexpected host.")
            while chunk := r.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_INSTALLER_BYTES:
                    raise UpdateError("The installer is larger than the safety limit; aborted.")
                h.update(chunk)
                f.write(chunk)
                if progress:
                    progress(total, info.size)
    except (urllib.error.URLError, OSError) as e:
        part.unlink(missing_ok=True)
        raise UpdateError(f"Download failed: {e}") from None
    except UpdateError:
        part.unlink(missing_ok=True)
        raise
    if h.hexdigest() != expected:
        part.unlink(missing_ok=True)
        raise UpdateError("Checksum mismatch: the download was corrupted or tampered with, so it was discarded.")
    os.replace(part, target)
    return Downloaded(target, expected, info.version)


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def launch_installer(d: Downloaded) -> None:
    """Run the verified installer silently. Windows shows its administrator prompt (UAC)."""
    if _sha256_file(d.path) != d.sha256:
        raise UpdateError("The downloaded installer changed after it was verified; not running it.")
    if sys.platform != "win32":
        raise UpdateError("Installing updates is only supported on Windows.")
    import ctypes
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", str(d.path), "/SILENT /CLOSEAPPLICATIONS", None, 1)
    if rc <= 32:
        raise UpdateError("The installer did not start (was the administrator prompt declined?).")


# ---- small persisted state: when we last checked, which version the user skipped -------------------------
def _state_path() -> Path:
    return config.DATA_DIR / "update_state.json"


def load_state() -> dict:
    try:
        return json.loads(_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_state(s: dict) -> None:
    try:
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        _state_path().write_text(json.dumps(s), encoding="utf-8")
    except OSError:
        pass


def due(min_interval: float, now: Callable[[], float] = time.time) -> bool:
    """True if we haven't checked within min_interval seconds. Records this check."""
    s = load_state()
    if now() - s.get("last_check", 0) < min_interval:
        return False
    s["last_check"] = now()
    _save_state(s)
    return True


def skip_version(version: str) -> None:
    s = load_state()
    s["skipped"] = version
    _save_state(s)


def is_skipped(version: str) -> bool:
    return load_state().get("skipped") == version
