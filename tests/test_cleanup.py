import os
import time
from pathlib import Path

import pytest

from aegisguard.modules import cleanup


def mkfile(p: Path, size=100, age_days=10):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"x" * size)
    t = time.time() - age_days * 86400
    os.utime(p, (t, t))
    return p


def test_scan_only_returns_old_files(tmp_path):
    t = tmp_path / "t"
    mkfile(t / "old.tmp", 100, 10)
    mkfile(t / "sub" / "old2.tmp", 50, 5)
    mkfile(t / "new.tmp", 10, 0)
    cands = cleanup.scan_cleanup({"Temp": [t]}, min_age_days=2)
    assert sorted(Path(c.path).name for c in cands) == ["old.tmp", "old2.tmp"]
    assert cleanup.summarize(cands) == {"Temp": (2, 150)}


def test_clean_requires_approval(tmp_path):
    t = tmp_path / "t"
    f = mkfile(t / "a.tmp")
    cands = cleanup.scan_cleanup({"Temp": [t]})
    assert cleanup.clean(cands, approved=False, tgts={"Temp": [t]}) == (0, 0, 0)
    assert f.exists()


def test_clean_deletes_and_reports_bytes(tmp_path):
    t = tmp_path / "t"
    f = mkfile(t / "a.tmp", 123)
    cands = cleanup.scan_cleanup({"Temp": [t]})
    assert cleanup.clean(cands, approved=True, tgts={"Temp": [t]}) == (123, 1, 0)
    assert not f.exists()


def test_clean_refuses_files_outside_allowed_folders(tmp_path):
    t = tmp_path / "t"; t.mkdir()
    precious = mkfile(tmp_path / "Documents" / "thesis.docx")
    fake = [cleanup.Candidate(str(precious), 100, "Temp")]
    assert cleanup.clean(fake, approved=True, tgts={"Temp": [t]}) == (0, 0, 1)
    assert precious.exists()


def test_symlinks_are_not_followed_or_deleted(tmp_path):
    t = tmp_path / "t"; t.mkdir()
    target = mkfile(tmp_path / "elsewhere" / "keep.txt")
    try:
        (t / "link.txt").symlink_to(target)
    except OSError:
        pytest.skip("symlinks not permitted here")
    assert cleanup.scan_cleanup({"Temp": [t]}) == []
    forged = [cleanup.Candidate(str(t / "link.txt"), 1, "Temp")]
    assert cleanup.clean(forged, approved=True, tgts={"Temp": [t]})[1] == 0
    assert target.exists()


def test_largest_items_sorted(tmp_path):
    mkfile(tmp_path / "big" / "a.bin", 5000)
    mkfile(tmp_path / "small" / "b.bin", 10)
    mkfile(tmp_path / "loose.bin", 700)
    items, complete = cleanup.largest_items(tmp_path)
    assert [Path(p).name for p, _ in items] == ["big", "loose.bin", "small"] and complete


def test_largest_items_honours_time_budget(tmp_path):
    mkfile(tmp_path / "big" / "a.bin", 5000)
    ticks = iter(range(1000))
    items, complete = cleanup.largest_items(tmp_path, max_seconds=0, clock=lambda: next(ticks))
    assert complete is False


def test_human():
    assert cleanup.human(512) == "512 B"
    assert cleanup.human(5 * 1024 * 1024) == "5.0 MB"
