import pytest

from aegisguard.core import config
from aegisguard.modules import quarantine


@pytest.fixture(autouse=True)
def qdir(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "QUARANTINE_DIR", tmp_path / "quarantine")


def test_quarantine_and_restore_roundtrip(tmp_path):
    f = tmp_path / "bad.exe"
    f.write_bytes(b"payload")
    item = quarantine.quarantine_file(f, "test")
    assert not f.exists()
    assert (config.QUARANTINE_DIR / f"{item.id}.quar").exists()
    assert [i.id for i in quarantine.list_items()] == [item.id]
    quarantine.restore(item.id)
    assert f.read_bytes() == b"payload"
    assert quarantine.list_items() == []


def test_restore_refuses_to_overwrite(tmp_path):
    f = tmp_path / "a.exe"
    f.write_bytes(b"1")
    item = quarantine.quarantine_file(f)
    f.write_bytes(b"2")
    with pytest.raises(quarantine.QuarantineError):
        quarantine.restore(item.id)
    assert f.read_bytes() == b"2"


def test_delete_removes_file_and_entry(tmp_path):
    f = tmp_path / "x.exe"
    f.write_bytes(b"1")
    item = quarantine.quarantine_file(f)
    quarantine.delete(item.id)
    assert quarantine.list_items() == []
    assert not (config.QUARANTINE_DIR / f"{item.id}.quar").exists()


def test_missing_file_rejected(tmp_path):
    with pytest.raises(quarantine.QuarantineError):
        quarantine.quarantine_file(tmp_path / "nope.exe")
