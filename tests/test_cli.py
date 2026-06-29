from __future__ import annotations

from typer.testing import CliRunner

from aws_security_auditor.cli import app
from aws_security_auditor.models import Finding, ScanReport, ScanSummary, Severity


def _report(findings: list[Finding]) -> ScanReport:
    return ScanReport(
        "123",
        "arn",
        None,
        None,
        ["us-east-1"],
        findings,
        [],
        ScanSummary(1, 1, 1, 0, 0.1),
    )


def test_fail_on_exits_nonzero(monkeypatch) -> None:
    monkeypatch.setattr(
        "aws_security_auditor.cli.run_scan",
        lambda _config: _report(
            [Finding(Severity.HIGH, "H", "EC2", "us-east-1", "sg-1", "High", "", "")]
        ),
    )

    result = CliRunner().invoke(app, ["scan", "--fail-on", "HIGH", "--no-color"])

    assert result.exit_code == 1


def test_notify_on_sends_slack_when_threshold_matches(monkeypatch) -> None:
    calls: list[tuple[str, Severity]] = []
    monkeypatch.setattr(
        "aws_security_auditor.cli.run_scan",
        lambda _config: _report(
            [Finding(Severity.HIGH, "H", "EC2", "us-east-1", "sg-1", "High", "", "")]
        ),
    )
    monkeypatch.setattr(
        "aws_security_auditor.cli.notify_slack",
        lambda report, webhook_url, threshold: calls.append((webhook_url, threshold)),
    )

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--notify-on",
            "HIGH",
            "--slack-webhook-url",
            "https://hooks.slack.test/example",
            "--no-color",
        ],
    )

    assert result.exit_code == 0
    assert calls == [("https://hooks.slack.test/example", Severity.HIGH)]


def test_notify_on_uses_env_webhook(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setenv("AWS_SECURITY_AUDITOR_SLACK_WEBHOOK_URL", "https://hooks.slack.test/env")
    monkeypatch.setattr(
        "aws_security_auditor.cli.run_scan",
        lambda _config: _report(
            [Finding(Severity.MEDIUM, "M", "S3", "global", "bucket", "Medium", "", "")]
        ),
    )
    monkeypatch.setattr(
        "aws_security_auditor.cli.notify_slack",
        lambda report, webhook_url, threshold: calls.append(webhook_url),
    )

    result = CliRunner().invoke(app, ["scan", "--notify-on", "MEDIUM", "--no-color"])

    assert result.exit_code == 0
    assert calls == ["https://hooks.slack.test/env"]


def test_notify_on_skips_when_threshold_does_not_match(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        "aws_security_auditor.cli.run_scan",
        lambda _config: _report(
            [Finding(Severity.LOW, "L", "Tags", "us-east-1", "i-1", "Low", "", "")]
        ),
    )
    monkeypatch.setattr(
        "aws_security_auditor.cli.notify_slack",
        lambda report, webhook_url, threshold: calls.append(webhook_url),
    )

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--notify-on",
            "HIGH",
            "--slack-webhook-url",
            "https://hooks.slack.test/example",
            "--no-color",
        ],
    )

    assert result.exit_code == 0
    assert calls == []


def test_slack_failure_does_not_fail_scan(monkeypatch) -> None:
    monkeypatch.setattr(
        "aws_security_auditor.cli.run_scan",
        lambda _config: _report(
            [Finding(Severity.HIGH, "H", "EC2", "us-east-1", "sg-1", "High", "", "")]
        ),
    )

    def fail_notify(*_args: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr("aws_security_auditor.cli.notify_slack", fail_notify)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--notify-on",
            "HIGH",
            "--slack-webhook-url",
            "https://hooks.slack.test/example",
            "--no-color",
        ],
    )

    assert result.exit_code == 0
    assert "Slack notification failed" in result.stderr
