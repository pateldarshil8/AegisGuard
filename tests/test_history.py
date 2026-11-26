import pytest

from aegisguard.core import config
from aegisguard.core.models import Finding, ScanResult, Severity
from aegisguard.core.scoring import security_score
from aegisguard.modules import history


@pytest.fixture(autouse=True)
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")


def f(sev, title, path=None):
    return Finding("m", title, Severity(sev), "d", "", path)


def res(*findings, files=0):
    return ScanResult(findings=list(findings), meta={"files_scanned": files})


def test_score_weights_and_floor():
    assert security_score([]) == 100
    assert security_score([f("critical", "a"), f("high", "b"), f("medium", "c"), f("low", "d")]) == 100 - 30 - 15 - 7 - 2
    assert security_score([f("critical", str(i)) for i in range(5)]) == 0


def test_record_and_recent_newest_first():
    r1, prev1 = history.record(res(f("high", "a"), files=10))
    r2, prev2 = history.record(res(files=20))
    assert prev1 is None and prev2.id == r1.id
    runs = history.recent()
    assert [r.id for r in runs] == [r2.id, r1.id]
    assert runs[1].score == 85 and runs[1].counts["high"] == 1 and runs[1].files_scanned == 10
    assert runs[0].score == 100


def test_changes_between_runs():
    a, _ = history.record(res(f("high", "fixed me"), f("low", "stays")))
    b, prev = history.record(res(f("low", "stays"), f("medium", "brand new")))
    new, resolved = history.changes(prev, b)
    assert [d["title"] for d in new] == ["brand new"]
    assert [d["title"] for d in resolved] == ["fixed me"]


def test_history_is_pruned(monkeypatch):
    monkeypatch.setattr(history, "MAX_RUNS", 3)
    for i in range(6):
        history.record(res(f("low", str(i))))
    runs = history.recent()
    assert len(runs) == 3 and runs[0].findings[0]["title"] == "5"
