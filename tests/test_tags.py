from __future__ import annotations

from aws_hygiene_auditor.checks.tags import missing_tag_findings


def test_missing_required_tags() -> None:
    findings = missing_tag_findings(
        "EC2",
        "us-east-1",
        "i-1",
        [{"Key": "Owner", "Value": "ops"}],
        ("Owner", "Environment"),
    )
    assert findings[0].check_id == "RESOURCE_MISSING_REQUIRED_TAGS"
    assert "Environment" in findings[0].description
