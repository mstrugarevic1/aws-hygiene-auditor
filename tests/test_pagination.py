from __future__ import annotations

from aws_hygiene_auditor.checks.rds import scan_rds


class PagedRds:
    def paginate(self, operation: str, **kwargs: object):
        return iter(
            [
                {"DBInstances": [{"DBInstanceIdentifier": "db-1", "BackupRetentionPeriod": 1}]},
                {"DBInstances": [{"DBInstanceIdentifier": "db-2", "BackupRetentionPeriod": 1}]},
            ]
        )


def test_multiple_pages_are_processed() -> None:
    result = scan_rds(PagedRds(), "us-east-1")  # type: ignore[arg-type]
    assert result.resources == 2
    assert [f.resource_id for f in result.findings] == ["db-1", "db-2"]
