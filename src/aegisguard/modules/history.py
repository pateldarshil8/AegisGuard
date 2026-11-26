"""Scan history: every full check is stored (score, severity counts, findings) in data\\history.db (SQLite)
so you can see the trend and what changed since the previous check."""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime

from ..core import config
from ..core.models import ScanResult
from ..core.scoring import security_score

MAX_RUNS = 200
SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class Run:
    id: int
    started: str
    score: int
    counts: dict[str, int]
    files_scanned: int
    findings: list[dict]


def _connect() -> sqlite3.Connection:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(config.DATA_DIR / "history.db")
    con.execute("""CREATE TABLE IF NOT EXISTS runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, started TEXT NOT NULL, score INTEGER NOT NULL,
        critical INTEGER, high INTEGER, medium INTEGER, low INTEGER, info INTEGER,
        files_scanned INTEGER, findings TEXT NOT NULL)""")
    return con


def _row(r: tuple) -> Run:
    return Run(r[0], r[1], r[2], dict(zip(SEVERITIES, r[3:8])), r[8] or 0, json.loads(r[9]))


_COLS = "id, started, score, critical, high, medium, low, info, files_scanned, findings"


def _latest(con: sqlite3.Connection) -> Run | None:
    r = con.execute(f"SELECT {_COLS} FROM runs ORDER BY id DESC LIMIT 1").fetchone()
    return _row(r) if r else None


def record(result: ScanResult) -> tuple[Run, Run | None]:
    """Store a run. Returns (this run, the previous run or None)."""
    counts = {s: sum(1 for f in result.findings if f.severity.value == s) for s in SEVERITIES}
    score = security_score(result.findings)
    started = datetime.now().isoformat(timespec="seconds")
    findings = [f.to_dict() for f in result.findings]
    with closing(_connect()) as con:
        prev = _latest(con)
        cur = con.execute(
            "INSERT INTO runs (started, score, critical, high, medium, low, info, files_scanned, findings) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (started, score, *(counts[s] for s in SEVERITIES), result.meta.get("files_scanned", 0),
             json.dumps(findings)))
        con.execute("DELETE FROM runs WHERE id NOT IN (SELECT id FROM runs ORDER BY id DESC LIMIT ?)", (MAX_RUNS,))
        con.commit()
        run = Run(cur.lastrowid, started, score, counts, result.meta.get("files_scanned", 0), findings)
    return run, prev


def recent(limit: int = 30) -> list[Run]:
    """Newest first."""
    with closing(_connect()) as con:
        return [_row(r) for r in con.execute(
            f"SELECT {_COLS} FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]


def _key(d: dict) -> tuple:
    return d["module"], d["title"], d["detail"], d["path"]


def changes(prev: Run, cur: Run) -> tuple[list[dict], list[dict]]:
    """(new findings, resolved findings) going from prev to cur."""
    before, after = {_key(d) for d in prev.findings}, {_key(d) for d in cur.findings}
    return ([d for d in cur.findings if _key(d) not in before],
            [d for d in prev.findings if _key(d) not in after])
