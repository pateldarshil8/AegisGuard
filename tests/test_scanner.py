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
