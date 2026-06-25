from __future__ import annotations

from aws_hygiene_auditor.models import ScanReport, Severity


def render_markdown(report: ScanReport) -> str:
    lines = [
        "# AWS Hygiene Auditor Report",
        "",
        f"- Account: `{report.account_id}`",
        f"- ARN: `{report.arn}`",
        f"- Regions scanned: {len(report.regions)}",
        "",
        "| Severity | Region | Service | Resource | Finding |",
        "| --- | --- | --- | --- | --- |",
    ]
    for f in report.findings:
        lines.append(
            f"| {f.severity.value} | {f.region} | {f.service} | {f.resource_id} | {f.title} |"
        )
    counts = {s: sum(1 for f in report.findings if f.severity == s) for s in Severity}
    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- Scanned regions: {report.summary.scanned_regions}",
            f"- Checks executed: {report.summary.checks_executed}",
            f"- Resources inspected: {report.summary.resources_inspected}",
            f"- HIGH: {counts[Severity.HIGH]}",
            f"- MEDIUM: {counts[Severity.MEDIUM]}",
            f"- LOW: {counts[Severity.LOW]}",
            f"- Errors: {report.summary.errors}",
            f"- Duration: {report.summary.duration_seconds}s",
        ]
    )
    return "\n".join(lines) + "\n"
