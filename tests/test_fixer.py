from aegisguard.modules import fixer


def fake_reg(values):
    return lambda path, name: values.get((path.split("\\")[-1], name))


def test_flags_uac_smb1_rdp_and_defender():
    reg = fake_reg({
        ("System", "EnableLUA"): 0,
        ("Parameters", "SMB1"): 1,
        ("Terminal Server", "fDenyTSConnections"): 0,
    })
    res, fixes = fixer.propose(reg=reg, run_entries={}, defender_on=False)
    titles = " | ".join(f.title for f in res.findings)
    for expected in ("UAC", "SMBv1", "Remote Desktop", "Defender"):
        assert expected in titles
    assert len(fixes) == 4


def test_clean_system_has_no_findings():
    res, fixes = fixer.propose(reg=lambda p, n: None, run_entries={"Teams": r"C:\Program Files\Teams\t.exe"},
                               defender_on=True)
    assert res.findings == [] and fixes == []


def test_suspicious_startup_reported_without_auto_fix():
    res, fixes = fixer.propose(reg=lambda p, n: None,
                               run_entries={"x": r"C:\Users\a\AppData\Local\Temp\evil.exe"}, defender_on=True)
    assert len(res.findings) == 1 and fixes == []


def test_apply_requires_approval():
    res, fixes = fixer.propose(reg=fake_reg({("System", "EnableLUA"): 0}), run_entries={}, defender_on=True)
    ok, msg = fixer.apply(fixes[0], approved=False)
    assert ok is False and "not approved" in msg
