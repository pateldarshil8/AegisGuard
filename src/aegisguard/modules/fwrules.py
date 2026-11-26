"""Firewall rule management: block a program or an internet IP, list/remove our own rules.

Rules are built as argument lists (never a shell string) from validated input, and every rule is
named with RULE_PREFIX so AegisGuard only ever lists or removes rules it created.
Applying a rule is always a separate, user-approved step (see fixer.apply / remediation).
"""
from __future__ import annotations

import ipaddress
import subprocess
from pathlib import PureWindowsPath

from ..core import proc
from ..core.models import Finding, Severity
from .fixer import Fix

RULE_PREFIX = "AegisGuard Block"
_BAD_CHARS = set('"&|<>^%\r\n')


class RuleError(ValueError):
    pass


def _netsh(*args: str) -> list[str]:
    return ["netsh", "advfirewall", "firewall", *args]


def block_program_commands(exe_path: str) -> list[list[str]]:
    p = PureWindowsPath(exe_path)
    if not p.is_absolute() or p.suffix.lower() != ".exe":
        raise RuleError("Need the full path to a .exe file.")
    if any(c in _BAD_CHARS for c in exe_path):
        raise RuleError("Path contains invalid characters.")
    return [_netsh("add", "rule", f"name={RULE_PREFIX} - {p.name} ({d})", f"dir={d}", "action=block",
                   f"program={exe_path}", "enable=yes") for d in ("out", "in")]


def block_ip_commands(ip: str) -> list[list[str]]:
    try:
        a = ipaddress.ip_address(ip.strip())
    except ValueError as e:
        raise RuleError("Not a valid IP address.") from e
    if a.is_private or a.is_loopback or a.is_link_local or a.is_unspecified or a.is_multicast:
        raise RuleError("Refusing to block a local/private address (it could cut off your own network).")
    return [_netsh("add", "rule", f"name={RULE_PREFIX} - {a} ({d})", f"dir={d}", "action=block",
                   f"remoteip={a}", "enable=yes") for d in ("out", "in")]


def block_commands(target: str) -> list[list[str]]:
    """Target is either an IP address or the full path of a program."""
    try:
        ipaddress.ip_address(target.strip())
    except ValueError:
        return block_program_commands(target)
    return block_ip_commands(target)


def remove_command(rule_name: str) -> list[str]:
    if not rule_name.startswith(RULE_PREFIX) or any(c in _BAD_CHARS for c in rule_name):
        raise RuleError("Can only remove rules created by AegisGuard.")
    return _netsh("delete", "rule", f"name={rule_name}")


def list_rules() -> list[str]:
    try:
        r = proc.run(_netsh("show", "rule", "name=all"), capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return []
    names: list[str] = []
    for line in r.stdout.splitlines():
        if line.lower().startswith("rule name:"):
            n = line.split(":", 1)[1].strip()
            if n.startswith(RULE_PREFIX) and n not in names:
                names.append(n)
    return names


def propose_blocks(findings: list[Finding]) -> list[Fix]:
    """Turn high-severity network findings about a specific program into approval-gated block proposals."""
    fixes, done = [], set()
    for f in findings:
        if f.module != "netmon" or f.severity != Severity.HIGH or not f.path or f.path in done:
            continue
        try:
            cmds = block_program_commands(f.path)
        except RuleError:
            continue
        done.add(f.path)
        fixes.append(Fix(f, f"Block {f.path} from sending or receiving network traffic.", cmds[0], True, cmds[1:]))
    return fixes
