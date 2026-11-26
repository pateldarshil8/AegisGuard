import hashlib
import io

import pytest

from aegisguard.core import config
from aegisguard.modules import updater

INSTALLER = b"pretend-installer-bytes" * 100
SHA = hashlib.sha256(INSTALLER).hexdigest()
GH = "https://github.com/pateldarshil8/AegisGuard/releases/download/v1.0.1/"


def release(tag="v1.0.1", assets=None, notes="fixes"):
    if assets is None:
        assets = [
            {"name": "AegisGuardSetup-1.0.1.exe", "browser_download_url": GH + "AegisGuardSetup-1.0.1.exe", "size": len(INSTALLER)},
            {"name": "AegisGuardSetup-1.0.1.exe.sha256", "browser_download_url": GH + "AegisGuardSetup-1.0.1.exe.sha256", "size": 90},
        ]
    return {"tag_name": tag, "body": notes, "html_url": "https://github.com/x/y/releases/tag/" + tag, "assets": assets}


@pytest.fixture(autouse=True)
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")


def test_version_comparison():
    assert updater.is_newer("v1.0.1", "1.0.0")
    assert updater.is_newer("1.0.10", "1.0.9")
    assert updater.is_newer("1.1", "1.0.5")
    assert not updater.is_newer("1.0.0", "1.0.0")
    assert not updater.is_newer("0.9.9", "1.0.0")
    assert not updater.is_newer("nightly", "1.0.0")


def test_check_returns_info_for_newer_verified_release():
    info = updater.check("1.0.0", fetch_json=lambda url: release())
    assert info.version == "1.0.1" and info.installer_name == "AegisGuardSetup-1.0.1.exe" and info.notes == "fixes"


def test_check_none_when_up_to_date():
    assert updater.check("1.0.1", fetch_json=lambda url: release()) is None


def test_check_refuses_release_without_checksum():
    only_exe = release(assets=[{"name": "AegisGuardSetup-1.0.1.exe", "browser_download_url": GH + "AegisGuardSetup-1.0.1.exe"}])
    assert updater.check("1.0.0", fetch_json=lambda url: only_exe) is None


def test_check_refuses_foreign_hosts_and_odd_names():
    evil = release(assets=[
        {"name": "AegisGuardSetup-1.0.1.exe", "browser_download_url": "https://evil.example/a.exe"},
        {"name": "AegisGuardSetup-1.0.1.exe.sha256", "browser_download_url": GH + "x.sha256"}])
    assert updater.check("1.0.0", fetch_json=lambda url: evil) is None
    odd = release(assets=[{"name": "Other.exe", "browser_download_url": GH + "Other.exe"}])
    assert updater.check("1.0.0", fetch_json=lambda url: odd) is None


class Resp(io.BytesIO):
    def __init__(self, data, final_url):
        super().__init__(data)
        self._url = final_url

    def geturl(self): return self._url
    def __enter__(self): return self
    def __exit__(self, *a): return False


def make_opener(installer=INSTALLER, sha=SHA, installer_final=None):
    def opener(req, timeout):
        url = req.full_url
        if url.endswith(".sha256"):
            return Resp(f"{sha}  AegisGuardSetup-1.0.1.exe\n".encode(), url)
        return Resp(installer, installer_final or url)
    return opener


def info():
    return updater.check("1.0.0", fetch_json=lambda url: release())


def test_download_verifies_and_reports_progress(tmp_path):
    seen = []
    d = updater.download(info(), progress=lambda a, b: seen.append(a), opener=make_opener(), dest_dir=tmp_path)
    assert d.path.read_bytes() == INSTALLER and d.sha256 == SHA and seen[-1] == len(INSTALLER)
    assert not list(tmp_path.glob("*.part"))


def test_checksum_mismatch_discards_download(tmp_path):
    with pytest.raises(updater.UpdateError, match="Checksum mismatch"):
        updater.download(info(), opener=make_opener(installer=b"tampered"), dest_dir=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_redirect_to_other_host_is_rejected(tmp_path):
    with pytest.raises(updater.UpdateError, match="unexpected host"):
        updater.download(info(), opener=make_opener(installer_final="https://evil.example/x.exe"), dest_dir=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_oversized_download_aborts(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "MAX_INSTALLER_BYTES", 100)
    with pytest.raises(updater.UpdateError, match="safety limit"):
        updater.download(info(), opener=make_opener(), dest_dir=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_launch_refuses_file_changed_after_verification(tmp_path):
    f = tmp_path / "AegisGuardSetup-1.0.1.exe"
    f.write_bytes(b"swapped")
    with pytest.raises(updater.UpdateError, match="changed after"):
        updater.launch_installer(updater.Downloaded(f, SHA, "1.0.1"))


def test_check_interval_and_skip_state():
    t = [1000.0]
    assert updater.due(900, now=lambda: t[0]) is True
    t[0] += 60
    assert updater.due(900, now=lambda: t[0]) is False
    t[0] += 1000
    assert updater.due(900, now=lambda: t[0]) is True
    assert not updater.is_skipped("1.0.1")
    updater.skip_version("1.0.1")
    assert updater.is_skipped("1.0.1") and not updater.is_skipped("1.0.2")


def test_no_release_yet_means_up_to_date():
    import urllib.error

    def opener(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)

    assert updater._http_json(updater.API_URL, opener=opener) == {}
    assert updater.check("1.0.0", fetch_json=lambda url: {}) is None
