"""Quarantine: move a suspicious file into an inert, renamed copy with a manifest so it can be restored.

Nothing is ever deleted unless the user explicitly asks (delete()). System folders are protected.
"""
from __future__ import annotations

import json
import os
import shutil
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from ..core import config
from .scanner import sha256


class QuarantineError(Exception):
    pass


@dataclass
class Item:
    id: str
    original_path: str
    quarantined_at: str
    sha256: str | None
    reason: str
    size: int


def _manifest_path() -> Path:
    return config.QUARANTINE_DIR / "manifest.json"


def _load() -> dict[str, dict]:
    p = _manifest_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save(data: dict[str, dict]) -> None:
    config.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    _manifest_path().write_text(json.dumps(data, indent=2), encoding="utf-8")


def _protected_prefixes() -> tuple[str, ...]:
    vals = [os.environ.get(k) for k in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)")]
    return tuple(v.lower().rstrip("\\/") + os.sep for v in vals if v)


def quarantine_file(path: str | Path, reason: str = "") -> Item:
    src = Path(path).resolve()
    if not src.is_file():
        raise QuarantineError(f"Not a file: {src}")
    low = str(src).lower()
    if config.QUARANTINE_DIR.resolve() in src.parents:
        raise QuarantineError("File is already in quarantine.")
    if low.startswith(_protected_prefixes()):
        raise QuarantineError("Refusing to quarantine files in Windows/Program Files folders.")
    config.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    item = Item(uuid.uuid4().hex[:12], str(src), datetime.now().isoformat(timespec="seconds"),
                sha256(src), reason, src.stat().st_size)
    try:
        shutil.move(str(src), str(config.QUARANTINE_DIR / f"{item.id}.quar"))
    except OSError as e:
        raise QuarantineError(f"Could not move file: {e}") from e
    data = _load()
    data[item.id] = asdict(item)
    _save(data)
    return item


def list_items() -> list[Item]:
    return [Item(**v) for v in _load().values()]


def _get(item_id: str) -> tuple[dict, dict[str, dict]]:
    data = _load()
    if item_id not in data:
        raise QuarantineError(f"No quarantined item with id {item_id}")
    return data[item_id], data


def restore(item_id: str, overwrite: bool = False) -> str:
    entry, data = _get(item_id)
    dest = Path(entry["original_path"])
    stored = config.QUARANTINE_DIR / f"{item_id}.quar"
    if dest.exists() and not overwrite:
        raise QuarantineError(f"{dest} already exists; not overwriting.")
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(stored), str(dest))
    del data[item_id]
    _save(data)
    return str(dest)


def delete(item_id: str) -> None:
    _, data = _get(item_id)
    (config.QUARANTINE_DIR / f"{item_id}.quar").unlink(missing_ok=True)
    del data[item_id]
    _save(data)
