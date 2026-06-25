from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_hygiene_auditor.checks.base import CheckResult
from aws_hygiene_auditor.models import Finding, ScanError, Severity
from aws_hygiene_auditor.readonly_client import ReadOnlyAwsClient

DB_PORTS = {1433, 1521, 27017, 3306, 5432, 6379, 9200}


def _error(region: str, message: str) -> CheckResult:
    return CheckResult(errors=[ScanError("EC2", region, message)])


def _port_range(rule: dict[str, Any]) -> tuple[int, int] | None:
    if rule.get("IpProtocol") == "-1":
        return (0, 65535)
    if "FromPort" not in rule or "ToPort" not in rule:
        return None
    return int(rule["FromPort"]), int(rule["ToPort"])


def _contains(start: int, end: int, port: int) -> bool:
    return start <= port <= end


def _public(rule: dict[str, Any]) -> bool:
    return any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", [])) or any(
        r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", [])
    )


def scan_ec2(
    ec2: ReadOnlyAwsClient, region: str, account_id: str, snapshot_age_days: int
) -> CheckResult:
    result = CheckResult(checks=5)
    try:
        for page in ec2.paginate("describe_security_groups"):
            groups = page.get("SecurityGroups", [])
            result.resources += len(groups)
            for group in groups:
                result.findings.extend(_security_group_findings(group, region))

        for page in ec2.paginate("describe_addresses"):
            addresses = page.get("Addresses", [])
            result.resources += len(addresses)
            for address in addresses:
                if "AssociationId" not in address:
                    alloc = address.get("AllocationId") or address.get("PublicIp", "unknown")
                    result.findings.append(
                        Finding(
                            Severity.MEDIUM,
                            "EC2_UNUSED_EIP",
                            "EC2",
                            region,
                            alloc,
                            "Unused Elastic IP address",
                            "Elastic IP address is not associated with a resource.",
                            "Release unused Elastic IP addresses after confirming they "
                            "are not needed.",
                        )
                    )

        for page in ec2.paginate("describe_volumes"):
            volumes = page.get("Volumes", [])
            result.resources += len(volumes)
            for volume in volumes:
                result.findings.extend(_volume_findings(volume, region))

        cutoff = datetime.now(UTC) - timedelta(days=snapshot_age_days)
        for page in ec2.paginate("describe_snapshots", OwnerIds=[account_id]):
            snapshots = page.get("Snapshots", [])
            result.resources += len(snapshots)
            for snapshot in snapshots:
                started = snapshot.get("StartTime")
                if isinstance(started, datetime) and started < cutoff:
                    result.findings.append(
                        Finding(
                            Severity.LOW,
                            "EBS_OLD_SNAPSHOT",
                            "EBS",
                            region,
                            snapshot.get("SnapshotId", "unknown"),
                            "Old EBS snapshot",
                            f"Snapshot is older than {snapshot_age_days} days.",
                            "Review old snapshots and retain only those required by backup policy.",
                        )
                    )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        return _error(region, f"EC2 scan skipped: {exc}")
    return result


def _security_group_findings(group: dict[str, Any], region: str) -> list[Finding]:
    findings: list[Finding] = []
    group_id = group.get("GroupId", "unknown")
    for rule in group.get("IpPermissions", []):
        if not _public(rule):
            continue
        ports = _port_range(rule)
        if not ports:
            continue
        start, end = ports
        if start == 0 and end == 65535:
            title, severity, check = "All ports open to the world", Severity.HIGH, "EC2_SG_OPEN_ALL"
        elif _contains(start, end, 22):
            title, severity, check = "SSH open to the world", Severity.HIGH, "EC2_SG_OPEN_SSH"
        elif _contains(start, end, 3389):
            title, severity, check = "RDP open to the world", Severity.HIGH, "EC2_SG_OPEN_RDP"
        elif any(_contains(start, end, p) for p in DB_PORTS):
            title, severity, check = (
                "Database port open to the world",
                Severity.HIGH,
                "EC2_SG_OPEN_DB",
            )
        elif start in {80, 443} and end == start:
            continue
        else:
            title, severity, check = "Public ingress port", Severity.MEDIUM, "EC2_SG_PUBLIC_INGRESS"
        findings.append(
            Finding(
                severity,
                check,
                "EC2",
                region,
                group_id,
                title,
                f"Security group allows ingress from the internet on ports {start}-{end}.",
                "Restrict ingress to trusted CIDR ranges or remove the rule.",
            )
        )
    return findings


def _volume_findings(volume: dict[str, Any], region: str) -> list[Finding]:
    volume_id = volume.get("VolumeId", "unknown")
    findings: list[Finding] = []
    if volume.get("State") == "available":
        findings.append(
            Finding(
                Severity.MEDIUM,
                "EBS_UNATTACHED_VOLUME",
                "EBS",
                region,
                volume_id,
                "Unattached EBS volume",
                "Volume is available and unattached. "
                f"Size={volume.get('Size')}GiB Created={volume.get('CreateTime')} "
                f"Encrypted={volume.get('Encrypted')}",
                "Delete unused volumes after confirming no data retention requirement.",
            )
        )
    if volume.get("Encrypted") is False:
        findings.append(
            Finding(
                Severity.HIGH,
                "EBS_UNENCRYPTED_VOLUME",
                "EBS",
                region,
                volume_id,
                "Unencrypted EBS volume",
                "Volume encryption is disabled.",
                "Migrate data to encrypted storage.",
            )
        )
    return findings
