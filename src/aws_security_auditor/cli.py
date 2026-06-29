from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Annotated

import typer

from aws_security_auditor.config import ALL_SERVICES, DEFAULT_REQUIRED_TAGS, ScanConfig
from aws_security_auditor.models import SEVERITY_ORDER, ScanReport, Severity
from aws_security_auditor.notifiers.slack import notify_slack
from aws_security_auditor.reporting.console import render_console
from aws_security_auditor.reporting.csv_report import render_csv
from aws_security_auditor.reporting.json_report import render_json
from aws_security_auditor.reporting.markdown import render_markdown
from aws_security_auditor.scanner import run_scan

app = typer.Typer(help="Read-only AWS security auditor.")


@app.callback()
def main() -> None:
    """Read-only AWS security auditor."""


@app.command()
def scan(
    profile: Annotated[str | None, typer.Option(help="AWS profile name.")] = None,
    role_arn: Annotated[str | None, typer.Option(help="Optional role ARN to assume.")] = None,
    external_id: Annotated[str | None, typer.Option(help="External ID for AssumeRole.")] = None,
    regions: Annotated[str | None, typer.Option(help="Comma-separated AWS regions.")] = None,
    exclude_regions: Annotated[
        str | None, typer.Option(help="Comma-separated AWS regions to skip.")
    ] = None,
    services: Annotated[
        str | None, typer.Option(help="Comma-separated services to scan.")
    ] = None,
    output: Annotated[str, typer.Option(help="table, json, markdown, or csv.")] = "table",
    output_file: Annotated[Path | None, typer.Option(help="Write report to this path.")] = None,
    severity: Annotated[
        str | None, typer.Option(help="Only include findings at this severity or higher.")
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(help="Exit with status 1 when findings include this severity or higher."),
    ] = None,
    no_color: Annotated[bool, typer.Option(help="Disable terminal color.")] = False,
    verbose: Annotated[bool, typer.Option(help="Show skipped regions and warnings.")] = False,
    snapshot_age_days: Annotated[int, typer.Option(help="Old snapshot threshold.")] = 90,
    access_key_age_days: Annotated[int, typer.Option(help="Old access key threshold.")] = 90,
    required_tags: Annotated[str, typer.Option(help="Comma-separated required tags.")] = ",".join(
        DEFAULT_REQUIRED_TAGS
    ),
    max_workers: Annotated[int, typer.Option(help="Maximum regional scan worker threads.")] = 5,
    notify_on: Annotated[
        str | None,
        typer.Option(help="Send Slack notification when findings include this severity or higher."),
    ] = None,
    slack_webhook_url: Annotated[
        str | None,
        typer.Option(
            help="Slack webhook URL. Defaults to AWS_SECURITY_AUDITOR_SLACK_WEBHOOK_URL."
        ),
    ] = None,
) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(name)s %(message)s",
    )
    selected_regions = (
        tuple(r.strip() for r in regions.split(",") if r.strip()) if regions else None
    )
    excluded_regions = _csv(exclude_regions)
    selected_services = _services(services)
    tags = tuple(t.strip() for t in required_tags.split(",") if t.strip())
    config = ScanConfig(
        profile=profile,
        role_arn=role_arn,
        external_id=external_id,
        regions=selected_regions,
        exclude_regions=excluded_regions,
        services=selected_services,
        output=output,
        output_file=str(output_file) if output_file else None,
        severity=severity,
        fail_on=fail_on,
        no_color=no_color,
        verbose=verbose,
        snapshot_age_days=snapshot_age_days,
        access_key_age_days=access_key_age_days,
        required_tags=tags,
        max_workers=max_workers,
    )
    report = run_scan(config)
    if output == "table":
        render_console(report, no_color=no_color)
        text = render_markdown(report)
    elif output == "json":
        text = render_json(report)
        typer.echo(text)
    elif output == "markdown":
        text = render_markdown(report)
        typer.echo(text)
    elif output == "csv":
        text = render_csv(report)
        typer.echo(text)
    else:
        raise typer.BadParameter("output must be table, json, markdown, or csv")

    if output_file:
        output_file.write_text(text, encoding="utf-8")

    if notify_on:
        threshold = Severity(notify_on.upper())
        webhook_url = slack_webhook_url or os.environ.get("AWS_SECURITY_AUDITOR_SLACK_WEBHOOK_URL")
        if webhook_url and _has_findings_at_or_above(report, threshold):
            try:
                notify_slack(report, webhook_url, threshold)
            except Exception as exc:  # noqa: BLE001
                typer.echo(f"warning: Slack notification failed: {exc}", err=True)
        elif not webhook_url:
            typer.echo(
                "warning: Slack notification skipped: webhook URL is not configured",
                err=True,
            )

    if fail_on:
        threshold = Severity(fail_on.upper())
        if _has_findings_at_or_above(report, threshold):
            raise typer.Exit(1)


def _csv(value: str | None) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip()) if value else ()


def _services(value: str | None) -> tuple[str, ...] | None:
    services = tuple(item.lower() for item in _csv(value))
    unknown = sorted(set(services) - set(ALL_SERVICES))
    if unknown:
        raise typer.BadParameter(f"unknown services: {', '.join(unknown)}")
    return services or None


def _has_findings_at_or_above(report: ScanReport, threshold: Severity) -> bool:
    return any(SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[threshold] for f in report.findings)
