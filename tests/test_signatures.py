import io

import pytest

from aegisguard.core import config, settings
from aegisguard.modules import scanner, signatures

H1, H2 = "a" * 64, "B" * 64
KEY = "sk_secret_123"


@pytest.fixture(autouse=True)
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
    monkeypatch.delenv(signatures.KEY_ENV, raising=False)


def test_parse_hashes_from_csv_comments_and_noise():
    text = f'# header {H1}\n"2026-01-01","{H2}","x.exe","Emotet"\nnot a hash {"c" * 63}\n{"d" * 65}\n'
    assert signatures.parse_hashes(text) == {"b" * 64}


def test_build_url_needs_key_and_https():
    with pytest.raises(signatures.SignatureError):
        signatures.build_url(signatures.DEFAULT_FEED_URL, None)
    assert KEY in signatures.build_url(signatures.DEFAULT_FEED_URL, KEY)
    with pytest.raises(signatures.SignatureError):
        signatures.build_url("http://example.com/list.txt", None)
    assert signatures.build_url("https://example.com/list.txt", None) == "https://example.com/list.txt"


def test_update_writes_list_and_scanner_uses_it():
    r = signatures.update(settings.Settings(), key=KEY, fetcher=lambda url: f"{H1}\n{H2}\n")
    assert r.updated and r.count == 2
    assert signatures.status()["count"] == 2
    assert set(scanner.load_known_bad()) == {"a" * 64, "b" * 64}


def test_user_entries_take_precedence_over_feed():
    config.DATA_DIR.mkdir(parents=True)
    (config.DATA_DIR / "threat_hashes.txt").write_text(f"{H1} My own label\n")
    signatures.update(settings.Settings(), key=KEY, fetcher=lambda url: H1)
    assert scanner.load_known_bad()[H1] == "My own label"


def test_rate_limited_to_once_per_hour_unless_forced():
    t, calls = [1000.0], []

    def fetcher(url):
        calls.append(url)
        return H1

    s = settings.Settings()
    signatures.update(s, key=KEY, fetcher=fetcher, now=lambda: t[0])
    t[0] += 60
    r = signatures.update(s, key=KEY, fetcher=fetcher, now=lambda: t[0])
    assert not r.updated and len(calls) == 1
    signatures.update(s, key=KEY, fetcher=fetcher, now=lambda: t[0], force=True)
    assert len(calls) == 2
    t[0] += 4000
    signatures.update(s, key=KEY, fetcher=fetcher, now=lambda: t[0])
    assert len(calls) == 3


def test_empty_feed_never_overwrites_existing_list():
    s = settings.Settings()
    signatures.update(s, key=KEY, fetcher=lambda u: H1)
    with pytest.raises(signatures.SignatureError):
        signatures.update(s, key=KEY, fetcher=lambda u: "<html>login required</html>", force=True)
    assert signatures.feed_path().read_text().split() == ["a" * 64]


def test_fetch_errors_hide_the_key():
    def opener(req, timeout):
        raise OSError(f"cannot reach https://x/{KEY}/recent.csv")

    with pytest.raises(signatures.SignatureError) as e:
        signatures.fetch(f"https://x/{KEY}/recent.csv", KEY, opener=opener)
    assert KEY not in str(e.value) and "<key>" in str(e.value)


def test_fetch_rejects_oversized_download():
    class R(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    with pytest.raises(signatures.SignatureError):
        signatures.fetch("https://x/y", None, max_bytes=10, opener=lambda req, timeout: R(b"a" * 50))


def test_auto_update_is_silent_without_key():
    assert signatures.auto_update(settings.Settings()).findings == []
    assert signatures.status() is None
