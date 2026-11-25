from aegisguard.modules import fixer


def fake_reg(values):
    return lambda path, name: values.get((path.split("\\")[-1], name))


def test_flags_uac_smb1_rdp_and_defender():
    reg = fake_reg({
        ("System", "EnableLUA"): 0,
        ("Parameters", "SMB1"): 1,
        ("Terminal Server", "fDenyTSConnections"): 0,
    })
    res, fixes = fixer.propose(reg=reg, run_entries={}, defender_on=False, fw_states={})
    titles = " | ".join(f.title for f in res.findings)
    for expected in ("UAC", "SMBv1", "Remote Desktop", "Defender"):
        assert expected in titles
    assert len(fixes) == 4


def test_clean_system_has_no_findings():
    res, fixes = fixer.propose(reg=lambda p, n: None, run_entries={"Teams": r"C:\Program Files\Teams\t.exe"},
                               defender_on=True, fw_states={})
    assert res.findings == [] and fixes == []


def test_suspicious_startup_reported_without_auto_fix():
    res, fixes = fixer.propose(reg=lambda p, n: None,
                               run_entries={"x": r"C:\Users\a\AppData\Local\Temp\evil.exe"}, defender_on=True, fw_states={})
    assert len(res.findings) == 1 and fixes == []


def test_apply_requires_approval():
    res, fixes = fixer.propose(reg=fake_reg({("System", "EnableLUA"): 0}), run_entries={}, defender_on=True, fw_states={})
    ok, msg = fixer.apply(fixes[0], approved=False)
    assert ok is False and "not approved" in msg


def test_firewall_profile_off_gets_fix():
    res, fixes = fixer.propose(reg=lambda p, n: None, run_entries={}, defender_on=True,
                               fw_states={"Public": "OFF", "Private": "ON"})
    assert [f.title for f in res.findings] == ["Public firewall profile is OFF"]
    assert fixes[0].command[-3:] == ["publicprofile", "state", "on"] or "publicprofile" in fixes[0].command


def test_apply_runs_all_commands_and_stops_on_failure(monkeypatch):
    calls = []

    class R:
        def __init__(self, rc): self.returncode, self.stdout, self.stderr = rc, "", "boom"

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return R(1 if cmd == ["bad"] else 0)

    monkeypatch.setattr(fixer.subprocess, "run", fake_run)
    f = fixer.Finding("t", "x", fixer.Severity.INFO)
    assert fixer.apply(fixer.Fix(f, "d", ["a"], True, [["b"]]), True)[0] is True
    assert calls == [["a"], ["b"]]
    calls.clear()
    ok, msg = fixer.apply(fixer.Fix(f, "d", ["bad"], True, [["never"]]), True)
    assert ok is False and calls == [["bad"]]
