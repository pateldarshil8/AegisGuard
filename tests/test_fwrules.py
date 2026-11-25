import pytest

from aegisguard.core.models import Finding, Severity
from aegisguard.modules import fwrules


def test_block_program_builds_in_and_out_rules():
    cmds = fwrules.block_program_commands(r"C:\Users\a\Downloads\evil.exe")
    assert len(cmds) == 2
    assert all(c[:4] == ["netsh", "advfirewall", "firewall", "add"] and "action=block" in c for c in cmds)
    assert any("dir=out" in c for c in cmds) and any("dir=in" in c for c in cmds)
    assert all(c[5].startswith("name=AegisGuard Block") for c in cmds)


@pytest.mark.parametrize("bad", ["evil.exe", r"C:\x\evil.txt", r'C:\x\a" & calc.exe', "/tmp/evil.exe", ""])
def test_block_program_rejects_bad_paths(bad):
    with pytest.raises(fwrules.RuleError):
        fwrules.block_program_commands(bad)


@pytest.mark.parametrize("ip", ["192.168.1.1", "10.0.0.5", "127.0.0.1", "0.0.0.0", "169.254.1.1", "nonsense"])
def test_block_ip_refuses_local_or_invalid(ip):
    with pytest.raises(fwrules.RuleError):
        fwrules.block_ip_commands(ip)


def test_block_public_ip_ok_and_dispatch():
    cmds = fwrules.block_commands("8.8.4.4")
    assert any("remoteip=8.8.4.4" in c for c in cmds)
    assert "program=" in " ".join(fwrules.block_commands(r"C:\a\b.exe")[0])


def test_remove_only_our_rules():
    assert fwrules.remove_command("AegisGuard Block - x.exe (out)")[-1].startswith("name=AegisGuard Block")
    with pytest.raises(fwrules.RuleError):
        fwrules.remove_command("Core Networking - DNS (UDP-Out)")


def test_propose_blocks_only_for_high_netmon_with_path():
    hi = Finding("netmon", "t", Severity.HIGH, "d", "f", r"C:\Users\a\Temp\x.exe")
    low = Finding("netmon", "t", Severity.MEDIUM, "d", "f", r"C:\Users\a\Temp\y.exe")
    other = Finding("scanner", "t", Severity.HIGH, "d", "f", r"C:\Users\a\Temp\z.exe")
    fixes = fwrules.propose_blocks([hi, hi, low, other])
    assert len(fixes) == 1 and len(fixes[0].extra_commands) == 1
