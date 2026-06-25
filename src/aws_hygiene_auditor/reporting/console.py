from __future__ import annotations

import sys

from rich.console import Console
from rich.table import Table

from aws_hygiene_auditor.models import ScanReport, Severity

STYLES = {Severity.HIGH: "bold red", Severity.MEDIUM: "bold yellow", Severity.LOW: "bold cyan"}


def render_console(report: ScanReport, no_color: bool = False) -> None:
    console = Console(no_color=no_color or not sys.stdout.isatty())
    console.print(f"Account: {report.account_id}")
    console.print(f"ARN: {report.arn}")
    if report.profile:
        console.print(f"Profile: {report.profile}")
    if report.assumed_role:
        console.print(f"Assumed role: {report.assumed_role}")
    console.print(f"Regions scanned: {len(report.regions)}")

    table = Table()
    for column in ("Severity", "Region", "Service", "Resource", "Finding"):
        table.add_column(column)
    for f in report.findings:
        table.add_row(
            f.severity.value,
            f.region,
            f.service,
            f.resource_id,
            f.title,
            style=STYLES[f.severity],
        )
    console.print(table)

    counts = {s: sum(1 for f in report.findings if f.severity == s) for s in Severity}
    console.print(f"Scanned regions: {report.summary.scanned_regions}")
    console.print(f"Checks executed: {report.summary.checks_executed}")
    console.print(f"Resources inspected: {report.summary.resources_inspected}")
    console.print(f"HIGH: {counts[Severity.HIGH]}")
    console.print(f"MEDIUM: {counts[Severity.MEDIUM]}")
    console.print(f"LOW: {counts[Severity.LOW]}")
    console.print(f"Errors: {report.summary.errors}")
    console.print(f"Duration: {report.summary.duration_seconds}s")
    for error in report.errors:
        console.print(f"WARNING {error.region} {error.message}", style="yellow")
