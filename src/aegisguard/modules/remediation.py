"""One place that gathers every proposed fix (settings fixes + firewall block proposals)."""
from __future__ import annotations

from ..core.models import ScanResult
from . import fwrules, fixer, netmon


def propose_all() -> tuple[ScanResult, list[fixer.Fix]]:
    res, fixes = fixer.propose()
    blocks = fwrules.propose_blocks(netmon.run().findings)
    for fx in blocks:
        res.add(fx.finding)
    return res, fixes + blocks
