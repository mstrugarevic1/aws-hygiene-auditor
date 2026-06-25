from __future__ import annotations

from aws_hygiene_auditor.checks.rds import scan_rds


class FakeRds:
    def paginate(self, operation: str, **kwargs: object):
        return iter(
            [
                {
                    "DBInstances": [
                        {
                            "DBInstanceIdentifier": "db-1",
                            "PubliclyAccessible": True,
                            "StorageEncrypted": False,
                            "BackupRetentionPeriod": 0,
                        }
                    ]
                }
            ]
        )


def test_rds_findings() -> None:
    result = scan_rds(FakeRds(), "us-east-1")  # type: ignore[arg-type]
    assert {f.check_id for f in result.findings} == {
        "RDS_PUBLIC_INSTANCE",
        "RDS_UNENCRYPTED_INSTANCE",
        "RDS_BACKUPS_DISABLED",
    }
