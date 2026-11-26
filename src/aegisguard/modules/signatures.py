"""Threat-signature updates: download a public malware hash list so detection improves without a new release.

Default feed: abuse.ch MalwareBazaar "recent" export (free; needs a free abuse.ch Auth-Key in the environment
variable ABUSECH_AUTH_KEY). The feed's exact layout is not documented publicly, so we simply pull every 64-hex
SHA-256 out of whatever text comes back. Hashes are the only thing we read; nothing is ever executed.

Safety rules: HTTPS only, size-capped download, at most one fetch per hour (the provider's fair-use limit),
the key never appears in output or errors, and a bad/empty download never overwrites the existing list.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Callable
from urllib.parse import urlparse

from ..core import config, settings as settings_mod
from ..core.models import ScanResult

KEY_ENV = "ABUSECH_AUTH_KEY"
DEFAULT_FEED_URL = "https://mb-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
MIN_INTERVAL_SECONDS = 3600
MAX_BYTES = 100 * 1024 * 1024
HEX64 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")


class SignatureError(Exception):
    pass


@dataclass
class UpdateResult:
    updated: bool
    count: int
    message: str


def feed_path():
    return config.DATA_DIR / "threat_feed.txt"


def meta_path():
    return config.DATA_DIR / "threat_feed.meta.json"


def parse_hashes(text: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        out.update(h.lower() for h in HEX64.findall(line))
    return out


def redact(msg: str, key: str | None) -> str:
    return msg.replace(key, "<key>") if key else msg


def build_url(template: str, key: str | None) -> str:
    if "{auth_key}" in template:
        if not key:
            raise SignatureError(f"No Auth-Key found. Get a free one at https://auth.abuse.ch and set {KEY_ENV}.")
        url = template.replace("{auth_key}", key)
    else:
        url = template
    if not url.lower().startswith("https://"):
        raise SignatureError("Feed URL must use HTTPS.")
    return url


def fetch(url: str, key: str | None = None, max_bytes: int = MAX_BYTES, timeout: float = 30,
          opener: Callable = urllib.request.urlopen) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "AegisGuard/0.1"})
    try:
        with opener(req, timeout=timeout) as r:
            data = r.read(max_bytes + 1)
    except (urllib.error.URLError, OSError) as e:
        raise SignatureError(redact(f"Download failed: {e}", key)) from None
    if len(data) > max_bytes:
        raise SignatureError("Download is larger than the safety limit; aborted.")
    return data.decode("utf-8", errors="ignore")


def status() -> dict | None:
    try:
        return json.loads(meta_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def update(s: settings_mod.Settings | None = None, force: bool = False, key: str | None = None,
           fetcher: Callable[[str], str] | None = None, now: Callable[[], float] = time.time) -> UpdateResult:
    s = s or settings_mod.load()
    key = key if key is not None else os.environ.get(KEY_ENV)
    st = status()
    if st and not force and now() - st.get("fetched_at", 0) < MIN_INTERVAL_SECONDS:
        return UpdateResult(False, st.get("count", 0), "Already updated within the last hour (provider fair-use limit).")
    url = build_url(s.signature_feed_url, key)
    text = fetcher(url) if fetcher else fetch(url, key)
    hashes = parse_hashes(text)
    if not hashes:
        raise SignatureError("The feed contained no SHA-256 hashes (wrong key or the format changed). "
                             "Your existing list was left unchanged.")
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = feed_path().with_suffix(".tmp")
    tmp.write_text("\n".join(sorted(hashes)) + "\n", encoding="utf-8")
    os.replace(tmp, feed_path())  # atomic: scanner never sees a half-written list
    meta_path().write_text(json.dumps({
        "fetched_at": now(), "updated": datetime.now().isoformat(timespec="seconds"),
        "count": len(hashes), "source": urlparse(url).hostname}), encoding="utf-8")
    return UpdateResult(True, len(hashes), f"Loaded {len(hashes):,} hashes from {urlparse(url).hostname}.")


def auto_update(s: settings_mod.Settings) -> ScanResult:
    """Used by the background monitor. Silent when no key is configured; never raises."""
    if "{auth_key}" in s.signature_feed_url and not os.environ.get(KEY_ENV):
        return ScanResult()
    try:
        update(s)
    except (SignatureError, OSError):
        pass
    return ScanResult()
