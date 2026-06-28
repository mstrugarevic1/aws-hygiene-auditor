from __future__ import annotations

import sys

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from aws_security_auditor.models import ScanReport, Severity
from aws_security_auditor.reporting.regions import region_label

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

    table = Table(box=box.ASCII, show_lines=False)
    table.add_column("Severity", width=8)
    table.add_column("Region", min_width=16)
    table.add_column("Service", width=10)
    table.add_column("Resource", overflow="fold")
    table.add_column("Finding", ratio=2)
    for f in report.findings:
        table.add_row(
            Text(f.severity.value, style=STYLES[f.severity]),
            region_label(f.region),
            f.service,
            f.resource_id,
            f.title,
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
    if report.errors:
        console.print("Warnings:", style="yellow")
        for error in report.errors:
            console.print(
                f"{error.service} {region_label(error.region)}: {error.message}",
                style="yellow",
            )
