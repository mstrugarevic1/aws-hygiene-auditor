from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_hygiene_auditor.checks.base import CheckResult
from aws_hygiene_auditor.models import Finding, ScanError, Severity
from aws_hygiene_auditor.readonly_client import ReadOnlyAwsClient


def missing_tag_findings(
    service: str,
    region: str,
    resource_id: str,
    tags: list[dict[str, Any]],
    required: tuple[str, ...],
) -> list[Finding]:
    present = {t.get("Key") for t in tags}
    missing = [tag for tag in required if tag not in present]
    if not missing:
        return []
    return [
        Finding(
            Severity.LOW,
            "RESOURCE_MISSING_REQUIRED_TAGS",
            service,
            region,
            resource_id,
            "Missing required tags",
            f"Missing required tags: {', '.join(missing)}.",
            "Add the required governance tags.",
        )
    ]


def scan_regional_tags(
    ec2: ReadOnlyAwsClient,
    rds: ReadOnlyAwsClient,
    region: str,
    required: tuple[str, ...],
) -> CheckResult:
    result = CheckResult(checks=1)
    try:
        for page in ec2.paginate("describe_instances"):
            for reservation in page.get("Reservations", []):
                instances = reservation.get("Instances", [])
                result.resources += len(instances)
                for instance in instances:
                    result.findings.extend(
                        missing_tag_findings(
                            "EC2",
                            region,
                            instance.get("InstanceId", "unknown"),
                            instance.get("Tags", []),
                            required,
                        )
                    )
        for page in ec2.paginate("describe_volumes"):
            volumes = page.get("Volumes", [])
            result.resources += len(volumes)
            for volume in volumes:
                result.findings.extend(
                    missing_tag_findings(
                        "EBS",
                        region,
                        volume.get("VolumeId", "unknown"),
                        volume.get("Tags", []),
                        required,
                    )
                )
        for page in rds.paginate("describe_db_instances"):
            instances = page.get("DBInstances", [])
            result.resources += len(instances)
            for db in instances:
                result.findings.extend(
                    missing_tag_findings(
                        "RDS",
                        region,
                        db.get("DBInstanceIdentifier", "unknown"),
                        db.get("TagList", []),
                        required,
                    )
                )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        return CheckResult(errors=[ScanError("Tags", region, f"Tag scan skipped: {exc}")])
    return result
