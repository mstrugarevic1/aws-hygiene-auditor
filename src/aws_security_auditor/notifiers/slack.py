from __future__ import annotations

import json
import urllib.parse
import urllib.request

from aws_security_auditor.models import ScanReport, Severity


def notify_slack(report: ScanReport, webhook_url: str, threshold: Severity) -> None:
    parsed = urllib.parse.urlsplit(webhook_url)
    if parsed.scheme != "https":
        raise ValueError("Slack webhook URL must use https")
    payload = {"text": _message(report, threshold)}
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
        response.read()


def _message(report: ScanReport, threshold: Severity) -> str:
    counts = {
        severity: sum(1 for f in report.findings if f.severity == severity)
        for severity in Severity
    }
    lines = [
        f"AWS Security Auditor: account {report.account_id}",
        "",
        f"HIGH: {counts[Severity.HIGH]}",
        f"MEDIUM: {counts[Severity.MEDIUM]}",
        f"LOW: {counts[Severity.LOW]}",
        f"Regions: {report.summary.scanned_regions}",
        f"Duration: {report.summary.duration_seconds}s",
    ]
    top_findings = [f for f in report.findings if f.severity == threshold][:5]
    if top_findings:
        lines.extend(["", f"Top {threshold.value}:"])
        lines.extend(f"- {f.service} {f.resource_id}: {f.title}" for f in top_findings)
    return "\n".join(lines)
