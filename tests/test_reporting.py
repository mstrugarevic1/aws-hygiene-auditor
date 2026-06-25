from __future__ import annotations

from aws_hygiene_auditor.models import Finding, ScanReport, ScanSummary, Severity, sort_findings
from aws_hygiene_auditor.reporting.json_report import render_json
from aws_hygiene_auditor.reporting.markdown import render_markdown


def _report() -> ScanReport:
    return ScanReport(
        "123",
        "arn",
        None,
        None,
        ["us-east-1"],
        [
            Finding(Severity.LOW, "L", "EC2", "us-east-1", "i-1", "Low", "", ""),
            Finding(Severity.HIGH, "H", "EC2", "us-east-1", "i-2", "High", "", ""),
        ],
        [],
        ScanSummary(1, 1, 2, 0, 0.1),
    )


def test_severity_sorting() -> None:
    assert [f.severity for f in sort_findings(_report().findings)] == [Severity.HIGH, Severity.LOW]


def test_json_output_has_no_ansi() -> None:
    assert "\x1b[" not in render_json(_report())


def test_markdown_output() -> None:
    text = render_markdown(_report())
    assert "| Severity | Region | Service | Resource | Finding |" in text
    assert "## Summary" in text
