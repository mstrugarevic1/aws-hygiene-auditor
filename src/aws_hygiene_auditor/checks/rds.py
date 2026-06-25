from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from aws_hygiene_auditor.checks.base import CheckResult
from aws_hygiene_auditor.models import Finding, ScanError, Severity
from aws_hygiene_auditor.readonly_client import ReadOnlyAwsClient


def scan_rds(rds: ReadOnlyAwsClient, region: str) -> CheckResult:
    result = CheckResult(checks=4)
    try:
        for page in rds.paginate("describe_db_instances"):
            instances = page.get("DBInstances", [])
            result.resources += len(instances)
            for db in instances:
                dbid = db.get("DBInstanceIdentifier", "unknown")
                if db.get("PubliclyAccessible"):
                    result.findings.append(
                        Finding(
                            Severity.HIGH,
                            "RDS_PUBLIC_INSTANCE",
                            "RDS",
                            region,
                            dbid,
                            "Publicly accessible RDS instance",
                            "RDS instance is reachable from public networks.",
                            "Disable public accessibility unless explicitly required.",
                        )
                    )
                if db.get("StorageEncrypted") is False:
                    result.findings.append(
                        Finding(
                            Severity.HIGH,
                            "RDS_UNENCRYPTED_INSTANCE",
                            "RDS",
                            region,
                            dbid,
                            "Unencrypted RDS instance",
                            "Storage encryption is disabled.",
                            "Use encrypted RDS storage.",
                        )
                    )
                retention = int(db.get("BackupRetentionPeriod", 0))
                if retention == 0:
                    result.findings.append(
                        Finding(
                            Severity.MEDIUM,
                            "RDS_BACKUPS_DISABLED",
                            "RDS",
                            region,
                            dbid,
                            "Automated backups disabled",
                            "Backup retention period is 0 days.",
                            "Enable automated backups.",
                        )
                    )
                elif retention < 7:
                    result.findings.append(
                        Finding(
                            Severity.LOW,
                            "RDS_BACKUP_RETENTION_LOW",
                            "RDS",
                            region,
                            dbid,
                            "Backup retention shorter than seven days",
                            f"Backup retention is {retention} days.",
                            "Set backup retention to at least seven days where practical.",
                        )
                    )
    except (ClientError, BotoCoreError, KeyError, TypeError, ValueError) as exc:
        return CheckResult(errors=[ScanError("RDS", region, f"RDS scan skipped: {exc}")])
    return result
