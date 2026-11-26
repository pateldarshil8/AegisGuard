import pytest

from aegisguard.core import admin, config


@pytest.fixture(autouse=True)
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(admin, "ITERATIONS", 1000)   # keep tests fast
    admin.lock()
    clock = {"t": 1_000_000.0}
    monkeypatch.setattr(admin, "_now", lambda: clock["t"])
    return clock


def test_no_password_means_authorized():
    assert not admin.is_set()
    assert admin.authorized()


def test_set_password_requires_length():
    ok, _ = admin.set_password("short")
    assert not ok and not admin.is_set()


def test_password_is_not_stored_in_plain_text():
    admin.set_password("correct horse battery")
    text = admin.path().read_text(encoding="utf-8")
    assert "correct horse" not in text
    assert admin.is_set()


def test_unlock_and_autolock(data_dir):
    admin.set_password("correct horse battery")
    admin.lock()
    assert not admin.authorized()
    assert admin.unlock("wrong password!!")[0] is False
    assert not admin.authorized()
    assert admin.unlock("correct horse battery")[0] is True
    assert admin.authorized()
    data_dir["t"] += admin.autolock_minutes() * 60 + 1
    assert not admin.authorized()


def test_lock_now():
    admin.set_password("correct horse battery")
    assert admin.authorized()
    admin.lock()
    assert not admin.authorized()


def test_wrong_guesses_trigger_delay(data_dir):
    admin.set_password("correct horse battery")
    admin.lock()
    for _ in range(admin.MAX_FREE_FAILURES):
        assert admin.unlock("nope nope nope")[0] is False
    assert admin.locked_out_seconds() > 0
    ok, msg = admin.unlock("correct horse battery")      # right password is refused during the delay
    assert not ok and "Try again" in msg
    data_dir["t"] += 3600
    assert admin.unlock("correct horse battery")[0] is True


def test_change_and_remove_need_current_password():
    admin.set_password("correct horse battery")
    assert admin.set_password("another long one", current="bad")[0] is False
    assert admin.set_password("another long one", current="correct horse battery")[0] is True
    assert admin.clear_password("bad")[0] is False
    assert admin.is_set()
    assert admin.clear_password("another long one")[0] is True
    assert not admin.is_set() and admin.authorized()


def test_corrupt_file_is_treated_as_unset():
    config.DATA_DIR.mkdir(parents=True)
    admin.path().write_text("not json", encoding="utf-8")
    assert not admin.is_set()
