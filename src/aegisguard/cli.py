from __future__ import annotations

import argparse
import sys
import time

from . import __version__
from .core import config
from .modules import firewall, fixer, health, netmon, quarantine, reports, scanner


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


def _quarantine_cmd(action: str, target: str | None) -> int:
    try:
        if action == "list":
            items = quarantine.list_items()
            for i in items:
                print(f"{i.id}  {i.quarantined_at}  {i.original_path}  ({i.reason})")
            print(f"{len(items)} item(s) in quarantine.")
        elif not target:
            print(f"'{action}' needs a path (add) or an item id (restore/delete).")
            return 2
        elif action == "add":
            i = quarantine.quarantine_file(target, "manual")
            print(f"Quarantined {i.original_path} as {i.id}")
        elif action == "restore":
            print(f"Restored to {quarantine.restore(target)}")
        elif action == "delete":
            if input(f"Permanently delete {target}? [y/N] ").strip().lower() == "y":
                quarantine.delete(target)
                print("Deleted.")
    except quarantine.QuarantineError as e:
        print(f"Error: {e}")
        return 1
    return 0


def _watch(interval: int) -> int:
    """Re-check connections every `interval` seconds; print only new findings. Ctrl+C to stop."""
    seen: set[tuple] = set()
    print(f"Watching network every {interval}s (Ctrl+C to stop)...")
    try:
        while True:
            for f in netmon.run().findings:
                key = (f.title, f.detail)
                if key not in seen:
                    seen.add(key)
                    print(f"[{f.severity.value.upper():8}] {f.title} - {f.detail}")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped.")
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
    nm = sub.add_parser("net", help="inspect network connections and listeners (read-only)")
    nm.add_argument("--watch", type=int, metavar="SECONDS", help="keep watching, printing new findings")
    qp = sub.add_parser("quarantine", help="list/add/restore/delete quarantined files")
    qp.add_argument("action", choices=["list", "add", "restore", "delete"])
    qp.add_argument("target", nargs="?", help="file path (add) or item id (restore/delete)")
    sub.add_parser("full", help="run all checks and write a report")
    sub.add_parser("ui", help="launch desktop UI")
    args = p.parse_args(argv)

    config.ensure_dirs()
    if args.cmd == "ui":
        try:
            from .ui.app import launch
        except ImportError:
            print("The UI needs PySide6. Install it with:  pip install -e .[ui]")
            return 1
        launch()
        return 0
    if args.cmd == "quarantine":
        return _quarantine_cmd(args.action, args.target)
    if args.cmd == "fix":
        return _fix_flow(args.yes)
    if args.cmd == "net" and args.watch:
        return _watch(args.watch)

    runners = {"health": [health.run], "scan": [scanner.run], "firewall": [firewall.run],
               "audit": [fixer.run], "net": [netmon.run],
               "full": [health.run, scanner.run, firewall.run, fixer.run, netmon.run]}[args.cmd]
    merged = reports.merge([r() for r in runners])
    md, _ = reports.write(merged)
    for f in merged.findings:
        print(f"[{f.severity.value.upper():8}] {f.module}: {f.title} {('- ' + f.detail) if f.detail else ''}")
    print(f"\n{len(merged.findings)} finding(s). Report: {md}")
    return 1 if any(f.severity.value in ("high", "critical") for f in merged.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
