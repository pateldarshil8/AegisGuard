from pathlib import Path

from aegisguard.modules import scanner


def _tree(tmp_path: Path) -> Path:
    (tmp_path / "a").mkdir()
    (tmp_path / "$Recycle.Bin").mkdir()
    (tmp_path / "a" / "notes.txt").write_text("hello")
    (tmp_path / "a" / "weird.dat").write_bytes(b"MZ" + b"\0" * 100)  # program header, unusual extension
    (tmp_path / "$Recycle.Bin" / "x.exe").write_bytes(b"MZ" + b"\0" * 10)
    return tmp_path


def test_deep_flags_program_hidden_in_unusual_extension(tmp_path):
    root = _tree(tmp_path)
    assert not scanner.run([root], "full").findings
    deep = scanner.run([root], "deep")
    assert any("disguised" in f.title for f in deep.findings)
    assert deep.meta["mode"] == "deep"


def test_full_and_deep_skip_recycle_bin(tmp_path):
    root = _tree(tmp_path)
    assert scanner.run([root], "full").meta["files_scanned"] == 2
    assert scanner.run([root], "quick").meta["files_scanned"] == 3


def test_cancel_and_progress(tmp_path):
    for i in range(450):
        (tmp_path / f"f{i}.txt").write_text("x")
    calls = []
    res = scanner.run([tmp_path], "custom", progress=lambda n, p: calls.append(n))
    assert res.meta["files_scanned"] == 450 and calls[-1] == 450 and 200 in calls
    res = scanner.run([tmp_path], "custom", cancelled=lambda: True)
    assert res.meta["stopped"] and res.meta["files_scanned"] == 0


def test_targets(tmp_path):
    assert scanner.targets("custom", [tmp_path]) == [tmp_path]
    assert scanner.targets("quick")
    assert scanner.targets("full") == scanner.targets("deep")
