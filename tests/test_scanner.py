from __future__ import annotations

from aws_security_auditor.checks.base import CheckResult
from aws_security_auditor.config import ScanConfig
from aws_security_auditor.models import Finding, Severity
from aws_security_auditor.scanner import run_scan


def test_scanning_continues_after_one_regional_error(monkeypatch) -> None:
    monkeypatch.setattr("aws_security_auditor.scanner.build_session", lambda config: object())
    monkeypatch.setattr(
        "aws_security_auditor.scanner.client",
        lambda *_args: type(
            "C", (), {"call": lambda self, op, **kw: {"Account": "1", "Arn": "arn"}}
        )(),
    )
    monkeypatch.setattr(
        "aws_security_auditor.scanner.discover_regions", lambda *_args: (["a", "b"], [])
    )
    monkeypatch.setattr("aws_security_auditor.scanner.scan_s3", lambda *_args: CheckResult())
    monkeypatch.setattr("aws_security_auditor.scanner.scan_iam", lambda *_args: CheckResult())

    def fake_region(
        session: object, region: str, account_id: str, config: ScanConfig
    ) -> CheckResult:
        if region == "a":
            raise RuntimeError("boom")
        return CheckResult()

    monkeypatch.setattr("aws_security_auditor.scanner._scan_region", fake_region)
    report = run_scan(ScanConfig(max_workers=1))
    assert report.summary.scanned_regions == 2
    assert report.summary.errors == 1


def test_severity_filter_is_minimum_threshold(monkeypatch) -> None:
    monkeypatch.setattr("aws_security_auditor.scanner.build_session", lambda config: object())
    monkeypatch.setattr(
        "aws_security_auditor.scanner.client",
        lambda *_args: type(
            "C", (), {"call": lambda self, op, **kw: {"Account": "1", "Arn": "arn"}}
        )(),
    )
    monkeypatch.setattr("aws_security_auditor.scanner.discover_regions", lambda *_args: (["a"], []))
    monkeypatch.setattr("aws_security_auditor.scanner.scan_s3", lambda *_args: CheckResult())
    monkeypatch.setattr("aws_security_auditor.scanner.scan_iam", lambda *_args: CheckResult())
    monkeypatch.setattr(
        "aws_security_auditor.scanner._scan_region",
        lambda *_args: CheckResult(
            findings=[
                Finding(Severity.HIGH, "H", "EC2", "a", "h", "High", "", ""),
                Finding(Severity.MEDIUM, "M", "EC2", "a", "m", "Medium", "", ""),
                Finding(Severity.LOW, "L", "EC2", "a", "l", "Low", "", ""),
            ]
        ),
    )

    report = run_scan(ScanConfig(severity="MEDIUM", max_workers=1))

    assert {f.check_id for f in report.findings} == {"H", "M"}


def test_exclude_regions_filters_discovered_regions(monkeypatch) -> None:
    monkeypatch.setattr("aws_security_auditor.scanner.build_session", lambda config: object())
    monkeypatch.setattr(
        "aws_security_auditor.scanner.client",
        lambda *_args: type(
            "C", (), {"call": lambda self, op, **kw: {"Account": "1", "Arn": "arn"}}
        )(),
    )
    monkeypatch.setattr(
        "aws_security_auditor.scanner.discover_regions",
        lambda *_args: (["eu-central-1", "us-east-1"], []),
    )
    monkeypatch.setattr("aws_security_auditor.scanner.scan_s3", lambda *_args: CheckResult())
    monkeypatch.setattr("aws_security_auditor.scanner.scan_iam", lambda *_args: CheckResult())
    monkeypatch.setattr("aws_security_auditor.scanner._scan_region", lambda *_args: CheckResult())

    report = run_scan(ScanConfig(exclude_regions=("us-east-1",), max_workers=1))

    assert report.regions == ["eu-central-1"]


def test_services_filter_runs_selected_checks(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr("aws_security_auditor.scanner.build_session", lambda config: object())
    monkeypatch.setattr(
        "aws_security_auditor.scanner.client",
        lambda *_args: type(
            "C", (), {"call": lambda self, op, **kw: {"Account": "1", "Arn": "arn"}}
        )(),
    )
    monkeypatch.setattr("aws_security_auditor.scanner.discover_regions", lambda *_args: (["a"], []))
    monkeypatch.setattr("aws_security_auditor.scanner.scan_s3", lambda *_args: calls.append("s3"))
    monkeypatch.setattr("aws_security_auditor.scanner.scan_iam", lambda *_args: calls.append("iam"))

    def fake_ec2(*_args: object) -> CheckResult:
        calls.append("ec2")
        return CheckResult()

    monkeypatch.setattr("aws_security_auditor.scanner.scan_ec2", fake_ec2)
    report = run_scan(ScanConfig(services=("ec2",), max_workers=1))

    assert report.regions == ["a"]
    assert calls == ["ec2"]


def test_default_scan_skips_account_baseline_checks(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr("aws_security_auditor.scanner.build_session", lambda config: object())
    monkeypatch.setattr(
        "aws_security_auditor.scanner.client",
        lambda *_args: type(
            "C", (), {"call": lambda self, op, **kw: {"Account": "1", "Arn": "arn"}}
        )(),
    )
    monkeypatch.setattr("aws_security_auditor.scanner.discover_regions", lambda *_args: (["a"], []))
    monkeypatch.setattr("aws_security_auditor.scanner.scan_s3", lambda *_args: CheckResult())
    monkeypatch.setattr("aws_security_auditor.scanner.scan_iam", lambda *_args: CheckResult())
    monkeypatch.setattr("aws_security_auditor.scanner.scan_ec2", lambda *_args: CheckResult())
    monkeypatch.setattr("aws_security_auditor.scanner.scan_elbv2", lambda *_args: CheckResult())
    monkeypatch.setattr("aws_security_auditor.scanner.scan_ecr", lambda *_args: CheckResult())
    monkeypatch.setattr("aws_security_auditor.scanner.scan_kms", lambda *_args: CheckResult())
    monkeypatch.setattr("aws_security_auditor.scanner.scan_rds", lambda *_args: CheckResult())
    monkeypatch.setattr(
        "aws_security_auditor.scanner.scan_regional_tags", lambda *_args: CheckResult()
    )
    monkeypatch.setattr(
        "aws_security_auditor.scanner.scan_cloudtrail",
        lambda *_args: calls.append("cloudtrail") or CheckResult(),
    )
    monkeypatch.setattr(
        "aws_security_auditor.scanner.scan_config",
        lambda *_args: calls.append("config") or CheckResult(),
    )
    monkeypatch.setattr(
        "aws_security_auditor.scanner.scan_guardduty",
        lambda *_args: calls.append("guardduty") or CheckResult(),
    )
    monkeypatch.setattr(
        "aws_security_auditor.scanner.scan_securityhub",
        lambda *_args: calls.append("securityhub") or CheckResult(),
    )

    run_scan(ScanConfig(max_workers=1))

    assert calls == []


def test_baseline_checks_run_when_explicitly_selected(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr("aws_security_auditor.scanner.build_session", lambda config: object())
    monkeypatch.setattr(
        "aws_security_auditor.scanner.client",
        lambda *_args: type(
            "C", (), {"call": lambda self, op, **kw: {"Account": "1", "Arn": "arn"}}
        )(),
    )
    monkeypatch.setattr("aws_security_auditor.scanner.discover_regions", lambda *_args: (["a"], []))
    monkeypatch.setattr(
        "aws_security_auditor.scanner.scan_cloudtrail",
        lambda *_args: calls.append("cloudtrail") or CheckResult(),
    )
    monkeypatch.setattr(
        "aws_security_auditor.scanner.scan_config",
        lambda *_args: calls.append("config") or CheckResult(),
    )

    run_scan(ScanConfig(services=("cloudtrail", "config"), max_workers=1))

    assert calls == ["cloudtrail", "config"]
