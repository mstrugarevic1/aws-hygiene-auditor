from __future__ import annotations

import pytest

from aws_security_auditor.models import ScanReport, ScanSummary, Severity
from aws_security_auditor.notifiers.slack import notify_slack


def test_slack_webhook_must_use_https() -> None:
    report = ScanReport("123", "arn", None, None, [], [], [], ScanSummary(0, 0, 0, 0, 0.1))

    with pytest.raises(ValueError, match="https"):
        notify_slack(report, "http://hooks.slack.test/example", Severity.HIGH)
