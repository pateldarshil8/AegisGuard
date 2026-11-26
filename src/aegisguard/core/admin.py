"""Optional administrator password for AegisGuard's own actions.

When a password is set, anything that changes the system or weakens protection (applying a fix, quarantine
restore/delete, disk cleanup, installing an update, pausing or quitting protection, changing the password) needs
it first. A correct password unlocks those actions for a short session, then they lock again.

This is an application lock. It stops someone sitting at an already-open AegisGuard from using it; it is not a
Windows security boundary, so keep your Windows account itself protected too. Only a salted PBKDF2 hash is stored.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time

from . import config

ITERATIONS = 240_000
MIN_LENGTH = 8
MAX_FREE_FAILURES = 5          # wrong guesses allowed before a delay starts
MAX_DELAY_SECONDS = 15 * 60
DEFAULT_AUTOLOCK_MINUTES = 10

_now = time.time
_unlocked_until = 0.0          # in-memory only; a restart always locks


def path():
    return config.DATA_DIR / "admin.json"


def _load() -> dict:
    try:
        raw = json.loads(path().read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(d: dict) -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = path().with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=2), encoding="utf-8")
    os.replace(tmp, path())


def _hash(password: str, salt: bytes, iterations: int | None = None) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations or ITERATIONS).hex()


def is_set() -> bool:
    d = _load()
    return bool(d.get("hash") and d.get("salt"))


def autolock_minutes() -> int:
    v = _load().get("autolock_minutes", DEFAULT_AUTOLOCK_MINUTES)
    return v if isinstance(v, int) and 1 <= v <= 120 else DEFAULT_AUTOLOCK_MINUTES


def set_autolock_minutes(minutes: int) -> None:
    d = _load()
    d["autolock_minutes"] = max(1, min(120, int(minutes)))
    _save(d)


def locked_out_seconds() -> int:
    """Seconds left before another password attempt is allowed (0 = allowed now)."""
    left = float(_load().get("locked_until", 0)) - _now()
    return int(left) + 1 if left > 0 else 0


def _check(password: str) -> tuple[bool, str]:
    """Verify without touching the unlock session. Applies and records the failure delay."""
    d = _load()
    if not (d.get("hash") and d.get("salt")):
        return True, ""
    wait = locked_out_seconds()
    if wait:
        return False, f"Too many wrong attempts. Try again in {wait} seconds."
    try:
        salt = bytes.fromhex(d["salt"])
        good = hmac.compare_digest(_hash(password, salt, int(d.get("iterations", ITERATIONS))), d["hash"])
    except (ValueError, TypeError):
        good = False
    if good:
        d["failures"] = 0
        d["locked_until"] = 0
        _save(d)
        return True, ""
    d["failures"] = int(d.get("failures", 0)) + 1
    over = d["failures"] - MAX_FREE_FAILURES
    if over >= 0:
        d["locked_until"] = _now() + min(MAX_DELAY_SECONDS, 30 * (2 ** over))
    _save(d)
    return False, "Wrong password."


def set_password(new: str, current: str = "") -> tuple[bool, str]:
    if len(new) < MIN_LENGTH:
        return False, f"Use at least {MIN_LENGTH} characters."
    if is_set():
        ok, msg = _check(current)
        if not ok:
            return False, msg
    salt = os.urandom(16)
    d = _load()
    d.update(salt=salt.hex(), iterations=ITERATIONS, hash=_hash(new, salt), failures=0, locked_until=0)
    _save(d)
    global _unlocked_until
    _unlocked_until = _now() + autolock_minutes() * 60
    return True, "Administrator password set."


def clear_password(current: str) -> tuple[bool, str]:
    if not is_set():
        return True, ""
    ok, msg = _check(current)
    if not ok:
        return False, msg
    d = _load()
    for k in ("salt", "hash", "iterations", "failures", "locked_until"):
        d.pop(k, None)
    _save(d)
    return True, "Administrator password removed."


def unlock(password: str) -> tuple[bool, str]:
    global _unlocked_until
    ok, msg = _check(password)
    if ok:
        _unlocked_until = _now() + autolock_minutes() * 60
    return ok, msg


def lock() -> None:
    global _unlocked_until
    _unlocked_until = 0.0


def is_unlocked() -> bool:
    return _now() < _unlocked_until


def authorized() -> bool:
    """True when no password is set, or the session is currently unlocked."""
    return (not is_set()) or is_unlocked()
