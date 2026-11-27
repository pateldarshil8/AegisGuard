"""User-editable settings stored as JSON in data\\settings.json (created with defaults on first save)."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from . import config


def _default_watch_dirs() -> list[str]:
    home = Path(os.environ.get("USERPROFILE", str(Path.home())))
    return [str(home / "Downloads"), str(home / "Desktop")]


@dataclass
class Settings:
    watch_dirs: list[str] = field(default_factory=_default_watch_dirs)
    exclusions: list[str] = field(default_factory=list)  # path prefixes the scanner/monitor should skip
    file_poll_seconds: int = 10
    process_seconds: int = 60
    network_seconds: int = 60
    audit_minutes: int = 60
    min_alert_severity: str = "medium"  # info | low | medium | high | critical
    check_updates: bool = True  # look for a newer release on GitHub when the app opens
    theme: str = "system"  # system | light | dark
    signature_feed_url: str = "https://mb-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"


def path() -> Path:
    return config.DATA_DIR / "settings.json"


def load() -> Settings:
    s = Settings()
    try:
        raw = json.loads(path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return s
    for f in fields(Settings):
        if f.name in raw and isinstance(raw[f.name], type(getattr(s, f.name))):
            setattr(s, f.name, raw[f.name])
    if s.theme not in ("system", "light", "dark"):
        s.theme = "system"
    return s


def save(s: Settings) -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    path().write_text(json.dumps(asdict(s), indent=2), encoding="utf-8")
