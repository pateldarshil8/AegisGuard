"""Report generation. Local Markdown and JSON reports."""
from __future__ import annotations

import json
from datetime import datetime

from ..core import config
from ..core.models import ScanResult

ORDER = ["critical", "high", "medium", "low", "info"]


def merge(results: list[ScanResult]) -> ScanResult:
    out = ScanResult()
    seen: set[tuple] = set()
    for r in results:
        for f in r.findings:  # the same issue can be reported by two modules; keep one
            key = (f.title, f.detail, f.path)
            if key not in seen:
                seen.add(key)
                out.findings.append(f)
        out.meta.update(r.meta)
    return out


def write(result: ScanResult) -> tuple[str, str]:
    config.ensure_dirs()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    jpath = config.REPORTS_DIR / f"report-{stamp}.json"
    mpath = config.REPORTS_DIR / f"report-{stamp}.md"
    jpath.write_text(json.dumps({"started": result.started, "meta": result.meta,
                                 "findings": [f.to_dict() for f in result.findings]}, indent=2), encoding="utf-8")
    lines = [f"# AegisGuard Report - {stamp}", "", f"Findings: {len(result.findings)}", ""]
    for sev in ORDER:
        for f in (x for x in result.findings if x.severity.value == sev):
            lines += [f"## [{sev.upper()}] {f.title}", f"- Module: {f.module}"]
            if f.path: lines.append(f"- Path: `{f.path}`")
            if f.detail: lines.append(f"- Detail: {f.detail}")
            if f.remediation: lines.append(f"- Fix: {f.remediation}")
            lines.append("")
    mpath.write_text("\n".join(lines), encoding="utf-8")
    return str(mpath), str(jpath)
