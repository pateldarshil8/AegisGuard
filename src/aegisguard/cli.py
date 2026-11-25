from __future__ import annotations

import argparse
import sys

from . import __version__
from .core import config
from .modules import firewall, fixer, health, reports, scanner


def _fix_flow(auto_yes: bool) -> int:
    res, fixes = fixer.propose()
    for f in res.findings:
        print(f"[{f.severity.value.upper():8}] {f.title} {('- ' + f.detail) if f.detail else ''}")
    if not fixes:
        print("\nNo auto-fixable issues found.")
        return 0
    print(f"\n{len(fixes)} fix(es) available. Nothing runs without your approval (admin rights may be needed).\n")
    for fx in fixes:
        print(f"* {fx.finding.title}\n  Fix: {fx.description}\n  Command: {' '.join(fx.command)}")
        ans = "y" if auto_yes else input("  Apply? [y/N] ").strip().lower()
        ok, msg = fixer.apply(fx, approved=ans == "y")
        print(f"  -> {'OK' if ok else 'not applied'}: {msg}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="aegisguard", description="AegisGuard AI endpoint security suite")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("health", help="CPU/memory/disk snapshot")
    sub.add_parser("scan", help="quick file scan")
    sub.add_parser("firewall", help="audit Windows Firewall state")
    sub.add_parser("audit", help="check for risky system settings (read-only)")
    fx = sub.add_parser("fix", help="propose fixes and apply the ones you approve")
    fx.add_argument("--yes", action="store_true", help="approve all (use with care)")
    sub.add_parser("full", help="run all checks and write a report")
    sub.add_parser("ui", help="launch desktop UI")
    args = p.parse_args(argv)

    config.ensure_dirs()
    if args.cmd == "ui":
        from .ui.app import launch
        launch()
        return 0
    if args.cmd == "fix":
        return _fix_flow(args.yes)

    runners = {"health": [health.run], "scan": [scanner.run], "firewall": [firewall.run],
               "audit": [fixer.run], "full": [health.run, scanner.run, firewall.run, fixer.run]}[args.cmd]
    merged = reports.merge([r() for r in runners])
    md, _ = reports.write(merged)
    for f in merged.findings:
        print(f"[{f.severity.value.upper():8}] {f.module}: {f.title} {('- ' + f.detail) if f.detail else ''}")
    print(f"\n{len(merged.findings)} finding(s). Report: {md}")
    return 1 if any(f.severity.value in ("high", "critical") for f in merged.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
