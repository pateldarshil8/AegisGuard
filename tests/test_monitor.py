import json
import os

import pytest

from aegisguard.core import config, settings
from aegisguard.core.models import Finding, ScanResult, Severity
from aegisguard.modules.monitor import FileWatcher, Monitor, Task


def finding(sev="high", title="t", detail="d", path=None):
    return Finding("m", title, Severity(sev), detail, "", path)


def result(*fs):
    return ScanResult(findings=list(fs))


@pytest.fixture(autouse=True)
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")


def make(tasks, clock, **kw):
    return Monitor(settings.Settings(**kw), tasks=tasks, clock=clock)


def test_alerts_once_per_issue():
    now = [0.0]
    m = make([Task("a", 10, lambda: result(finding()))], lambda: now[0])
    assert len(m.tick()) == 1
    now[0] = 20
    assert m.tick() == []


def test_min_severity_filters_low_findings():
    m = make([Task("a", 1, lambda: result(finding("low"), finding("high", "x")))], lambda: 0.0)
    assert [f.title for f in m.tick()] == ["x"]


def test_interval_is_respected():
    calls, now = [], [0.0]
    m = make([Task("a", 60, lambda: calls.append(1) or result())], lambda: now[0])
    m.tick(); now[0] = 30; m.tick(); now[0] = 61; m.tick()
    assert len(calls) == 2


def test_failing_task_does_not_stop_others():
    def boom():
        raise RuntimeError("nope")

    m = make([Task("bad", 1, boom), Task("ok", 1, lambda: result(finding()))], lambda: 0.0)
    assert len(m.tick()) == 1
    assert "bad" in m.errors[0]


def test_callback_and_log_file():
    got = []
    m = make([Task("a", 1, lambda: result(finding(title="boom")))], lambda: 0.0)
    m.on_alert = got.append
    m.tick()
    assert [f.title for f in got] == ["boom"]
    line = json.loads((config.DATA_DIR / "alerts.log").read_text().splitlines()[0])
    assert line["title"] == "boom" and line["severity"] == "high"


def test_watcher_ignores_existing_files_then_scans_new_ones(tmp_path):
    d = tmp_path / "dl"; d.mkdir()
    (d / "old.pdf.exe").write_bytes(b"MZ")
    t = [1_000_000.0]
    w = FileWatcher([str(d)], now=lambda: t[0])
    assert w.poll().findings == []  # baseline
    new = d / "invoice.pdf.exe"
    new.write_bytes(b"MZ")
    os.utime(new, (t[0] - 100, t[0] - 100))
    res = w.poll()
    assert [f.title for f in res.findings] == ["Double-extension executable"]
    assert w.poll().findings == []  # same file is not re-reported


def test_watcher_waits_for_file_to_finish_writing(tmp_path):
    d = tmp_path / "dl"; d.mkdir()
    t = [1_000_000.0]
    w = FileWatcher([str(d)], now=lambda: t[0])
    w.poll()
    f = d / "a.pdf.exe"
    f.write_bytes(b"MZ")
    os.utime(f, (t[0] - 0.1, t[0] - 0.1))
    assert w.poll().findings == []
    t[0] += 5
    assert len(w.poll().findings) == 1


def test_watcher_skips_partial_downloads_and_exclusions(tmp_path):
    d = tmp_path / "dl"; d.mkdir()
    (d / "skip").mkdir()
    t = [1_000_000.0]
    w = FileWatcher([str(d)], exclusions=[str(d / "skip")], now=lambda: t[0])
    w.poll()
    for p in (d / "x.pdf.exe.crdownload", d / "skip" / "y.pdf.exe"):
        p.write_bytes(b"MZ")
        os.utime(p, (t[0] - 100, t[0] - 100))
    assert w.poll().findings == []


def test_settings_roundtrip_and_bad_values(tmp_path):
    assert settings.load().min_alert_severity == "medium"
    s = settings.Settings(audit_minutes=5, exclusions=["C:\\x"])
    settings.save(s)
    assert settings.load().audit_minutes == 5
    settings.path().write_text(json.dumps({"audit_minutes": "oops", "file_poll_seconds": 3}))
    loaded = settings.load()
    assert loaded.audit_minutes == 60 and loaded.file_poll_seconds == 3
