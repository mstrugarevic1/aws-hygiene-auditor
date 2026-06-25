from __future__ import annotations

from botocore.exceptions import ClientError

from aws_hygiene_auditor.checks import s3 as s3_checks
from aws_hygiene_auditor.checks.s3 import bucket_region, scan_s3


class FakeS3:
    def call(self, operation: str, **kwargs: object) -> dict[str, object]:
        if operation == "get_bucket_location":
            return {"LocationConstraint": None}
        raise ClientError({"Error": {"Code": "NoSuchBucketPolicy"}}, operation)


def test_s3_us_east_1_empty_location() -> None:
    assert bucket_region(FakeS3(), "bucket") == "us-east-1"  # type: ignore[arg-type]


class PublicBucketS3:
    def call(self, operation: str, **kwargs: object) -> dict[str, object]:
        if operation == "list_buckets":
            return {"Buckets": [{"Name": "bucket"}]}
        if operation == "get_bucket_location":
            return {"LocationConstraint": None}
        if operation == "get_bucket_acl":
            return {
                "Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]
            }
        if operation == "get_bucket_policy_status":
            return {"PolicyStatus": {"IsPublic": True}}
        if operation == "get_bucket_public_access_block":
            return {"PublicAccessBlockConfiguration": {}}
        if operation == "get_bucket_versioning":
            return {}
        if operation == "get_bucket_logging":
            return {}
        if operation == "get_bucket_encryption":
            raise ClientError(
                {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}},
                operation,
            )
        raise AssertionError(operation)


class PublicBlockEnabled:
    def call(self, operation: str, **kwargs: object) -> dict[str, object]:
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }


def test_public_s3_bucket(monkeypatch) -> None:
    monkeypatch.setattr(
        s3_checks,
        "client",
        lambda _session, service, _region=None: (
            PublicBlockEnabled() if service == "s3control" else PublicBucketS3()
        ),
    )

    result = scan_s3(object(), PublicBucketS3(), "123")  # type: ignore[arg-type]
    assert {"S3_PUBLIC_ACL", "S3_PUBLIC_POLICY"} <= {f.check_id for f in result.findings}
