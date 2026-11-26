from __future__ import annotations

import argparse
import sys
import time

from . import __version__
from .core import config, settings
from pathlib import Path

from .modules import (cleanup, firewall, fixer, fwrules, health, monitor, netmon, processes, quarantine,
                      remediation, reports, scanner)


def _fix_flow(auto_yes: bool) -> int:
    res, fixes = remediation.propose_all()
    for f in res.findings:
        print(f"[{f.severity.value.upper():8}] {f.title} {('- ' + f.detail) if f.detail else ''}")
    if not fixes:
        print("\nNo auto-fixable issues found.")
        return 0
    print(f"\n{len(fixes)} fix(es) available. Nothing runs without your approval (admin rights may be needed).\n")
    for fx in fixes:
        cmds = "\n           ".join(' '.join(c) for c in [fx.command, *fx.extra_commands])
        print(f"* {fx.finding.title}\n  Fix: {fx.description}\n  Command: {cmds}")
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


def _block_cmd(action: str, target: str | None) -> int:
    try:
        if action == "rules":
            names = fwrules.list_rules()
            print("\n".join(names) if names else "No AegisGuard block rules.")
            return 0
        if not target:
            print(f"'{action}' needs a target.")
            return 2
        cmds = fwrules.block_commands(target) if action == "block" else [fwrules.remove_command(target)]
    except fwrules.RuleError as e:
        print(f"Error: {e}")
        return 1
    print("This will run:\n  " + "\n  ".join(" ".join(c) for c in cmds))
    if input("Apply? [y/N] ").strip().lower() != "y":
        print("Cancelled.")
        return 0
    fx = fixer.Fix(fixer.Finding("firewall", action, fixer.Severity.INFO), action, cmds[0], True, cmds[1:])
    ok, msg = fixer.apply(fx, approved=True)
    print(("Done: " if ok else "Failed: ") + msg + ("" if ok else "\n(Run from an administrator terminal.)"))
    return 0 if ok else 1


def _cleanup_cmd(min_age: float) -> int:
    print(f"Looking for temp files older than {min_age:g} day(s)...")
    cands = cleanup.scan_cleanup(min_age_days=min_age)
    if not cands:
        print("Nothing to clean.")
        return 0
    summary = cleanup.summarize(cands)
    for cat, (n, b) in summary.items():
        print(f"  {cat}: {n} file(s), {cleanup.human(b)}")
    total = sum(b for _, b in summary.values())
    print(f"Total: {cleanup.human(total)} in {len(cands)} file(s). Only these temp/cache folders are touched.")
    if input("Delete these files permanently? [y/N] ").strip().lower() != "y":
        print("Cancelled.")
        return 0
    freed, deleted, failed = cleanup.clean(cands, approved=True)
    print(f"Freed {cleanup.human(freed)} ({deleted} deleted, {failed} skipped because they are in use or protected).")
    return 0


def _space_cmd(path: str | None, top: int) -> int:
    root = Path(path) if path else Path.home()
    print(f"Measuring {root} (up to 45 seconds)...")
    items, complete = cleanup.largest_items(root, top)
    for p, size in items:
        print(f"{cleanup.human(size):>10}  {p}")
    if not complete:
        print("(Stopped at the time limit; sizes may be underestimated.)")
    return 0


def _monitor_cmd() -> int:
    s = settings.load()
    print("AegisGuard monitor running. Press Ctrl+C to stop.")
    print(f"  Watching: {', '.join(s.watch_dirs)}")
    print(f"  Alerting on {s.min_alert_severity}+ severity. Log: {config.DATA_DIR / 'alerts.log'}")

    def show(f):
        print(f"[{f.severity.value.upper():8}] {f.module}: {f.title} {('- ' + f.detail) if f.detail else ''}")

    m = monitor.Monitor(s, on_alert=show)
    try:
        m.run_forever()
    except KeyboardInterrupt:
        m.stop()
        print("\nStopped.")
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
    sc = sub.add_parser("scan", help="file scan (Downloads + Temp by default)")
    sc.add_argument("--path", action="append", help="scan this folder instead (repeatable)")
    sub.add_parser("procs", help="check running processes for signs of malware (read-only)")
    bp = sub.add_parser("block", help="block a program (full .exe path) or internet IP in Windows Firewall")
    bp.add_argument("target")
    up = sub.add_parser("unblock", help="remove an AegisGuard block rule by name")
    up.add_argument("target")
    sub.add_parser("rules", help="list AegisGuard firewall block rules")
    sub.add_parser("firewall", help="audit Windows Firewall state")
    sub.add_parser("audit", help="check for risky system settings (read-only)")
    fx = sub.add_parser("fix", help="propose fixes and apply the ones you approve")
    fx.add_argument("--yes", action="store_true", help="approve all (use with care)")
    nm = sub.add_parser("net", help="inspect network connections and listeners (read-only)")
    nm.add_argument("--watch", type=int, metavar="SECONDS", help="keep watching, printing new findings")
    qp = sub.add_parser("quarantine", help="list/add/restore/delete quarantined files")
    qp.add_argument("action", choices=["list", "add", "restore", "delete"])
    qp.add_argument("target", nargs="?", help="file path (add) or item id (restore/delete)")
    cl = sub.add_parser("cleanup", help="find and remove old temp/cache files (asks first)")
    cl.add_argument("--min-age", type=float, default=2, help="only files older than this many days (default 2)")
    sp = sub.add_parser("space", help="show which folders use the most disk space (read-only)")
    sp.add_argument("--path", help="folder to measure (default: your user folder)")
    sp.add_argument("--top", type=int, default=15)
    sub.add_parser("monitor", help="run background protection in this window (Ctrl+C to stop)")
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
    if args.cmd == "cleanup":
        return _cleanup_cmd(args.min_age)
    if args.cmd == "space":
        return _space_cmd(args.path, args.top)
    if args.cmd == "monitor":
        return _monitor_cmd()
    if args.cmd == "quarantine":
        return _quarantine_cmd(args.action, args.target)
    if args.cmd in ("block", "unblock", "rules"):
        return _block_cmd(args.cmd, getattr(args, "target", None))
    if args.cmd == "fix":
        return _fix_flow(args.yes)
    if args.cmd == "net" and args.watch:
        return _watch(args.watch)

    scan_run = (lambda: scanner.run([Path(p) for p in args.path])) if getattr(args, "path", None) else scanner.run
    runners = {"health": [health.run], "scan": [scan_run], "procs": [processes.run], "firewall": [firewall.run],
               "audit": [fixer.run], "net": [netmon.run],
               "full": [health.run, scanner.run, processes.run, firewall.run, fixer.run, netmon.run]}[args.cmd]
    merged = reports.merge([r() for r in runners])
    md, _ = reports.write(merged)
    for f in merged.findings:
        print(f"[{f.severity.value.upper():8}] {f.module}: {f.title} {('- ' + f.detail) if f.detail else ''}")
    print(f"\n{len(merged.findings)} finding(s). Report: {md}")
    return 1 if any(f.severity.value in ("high", "critical") for f in merged.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
