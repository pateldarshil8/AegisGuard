"""Security score: 100 minus points per finding (critical 30, high 15, medium 7, low 2, info 0), floor 0."""
from __future__ import annotations

from .models import Finding

SEV_WEIGHT = {"critical": 30, "high": 15, "medium": 7, "low": 2, "info": 0}


def security_score(findings: list[Finding]) -> int:
    return max(0, 100 - sum(SEV_WEIGHT[f.severity.value] for f in findings))
