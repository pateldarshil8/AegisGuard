from __future__ import annotations

import argparse
import sys

from . import __version__
from .core import config
from .modules import firewall, health, reports, scanner


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="aegisguard", description="AegisGuard AI endpoint security suite")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("health", help="CPU/memory/disk snapshot")
    sub.add_parser("scan", help="quick file scan")
    sub.add_parser("firewall", help="audit Windows Firewall state")
    sub.add_parser("full", help="run everything and write a report")
    sub.add_parser("ui", help="launch desktop UI")
    args = p.parse_args(argv)

    config.ensure_dirs()
    if args.cmd == "ui":
        from .ui.app import launch
        launch()
        return 0

    runners = {"health": [health.run], "scan": [scanner.run], "firewall": [firewall.run],
               "full": [health.run, scanner.run, firewall.run]}[args.cmd]
    merged = reports.merge([r() for r in runners])
    md, js = reports.write(merged)
    for f in merged.findings:
        print(f"[{f.severity.value.upper():8}] {f.module}: {f.title} {('- ' + f.detail) if f.detail else ''}")
    print(f"\n{len(merged.findings)} finding(s). Report: {md}")
    return 1 if any(f.severity.value in ("high", "critical") for f in merged.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
