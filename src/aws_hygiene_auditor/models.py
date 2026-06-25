from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum


class Severity(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}


@dataclass(frozen=True)
class Finding:
    severity: Severity
    check_id: str
    service: str
    region: str
    resource_id: str
    title: str
    description: str
    recommendation: str

    def to_dict(self) -> dict[str, str]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass(frozen=True)
class ScanError:
    service: str
    region: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class ScanSummary:
    scanned_regions: int
    checks_executed: int
    resources_inspected: int
    errors: int
    duration_seconds: float


@dataclass(frozen=True)
class ScanReport:
    account_id: str
    arn: str
    profile: str | None
    assumed_role: str | None
    regions: list[str]
    findings: list[Finding]
    errors: list[ScanError]
    summary: ScanSummary


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER[f.severity], f.region, f.service, f.resource_id),
    )
