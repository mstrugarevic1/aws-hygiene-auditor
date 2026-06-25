from __future__ import annotations

from dataclasses import dataclass, field

from aws_hygiene_auditor.models import Finding, ScanError


@dataclass
class CheckResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    resources: int = 0
    checks: int = 0
