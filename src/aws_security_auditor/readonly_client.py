from __future__ import annotations

from collections.abc import Iterator
from typing import Any

ALLOWED_OPERATIONS = {
    "sts": {"assume_role", "get_caller_identity"},
    "ec2": {
        "describe_addresses",
        "describe_images",
        "describe_instances",
        "describe_regions",
        "describe_snapshot_attribute",
        "describe_security_groups",
        "describe_snapshots",
        "describe_volumes",
        "get_ebs_encryption_by_default",
    },
    "cloudtrail": {"describe_trails", "get_trail_status"},
    "config": {"describe_configuration_recorders", "describe_configuration_recorder_status"},
    "guardduty": {"list_detectors"},
    "securityhub": {"describe_hub"},
    "elbv2": {"describe_load_balancers"},
    "ecr": {"describe_repositories"},
    "kms": {"get_key_rotation_status", "list_keys"},
    "rds": {"describe_db_instances"},
    "s3": {
        "get_bucket_acl",
        "get_bucket_encryption",
        "get_bucket_location",
        "get_bucket_logging",
        "get_bucket_policy",
        "get_bucket_policy_status",
        "get_bucket_public_access_block",
        "get_bucket_versioning",
        "list_buckets",
    },
    "s3control": {"get_public_access_block"},
    "iam": {
        "get_access_key_last_used",
        "get_account_password_policy",
        "get_account_summary",
        "get_login_profile",
        "list_access_keys",
        "list_mfa_devices",
        "list_user_policies",
        "list_users",
    },
}


class UnsafeAwsOperationError(RuntimeError):
    """Raised before boto3 is called for an operation this app does not approve."""


class ReadOnlyAwsClient:
    def __init__(self, service_name: str, client: Any):
        self.service_name = service_name
        self._client = client

    def call(self, operation: str, **kwargs: Any) -> dict[str, Any]:
        self._validate(operation)
        result = getattr(self._client, operation)(**kwargs)
        return result if isinstance(result, dict) else {}

    def paginate(self, operation: str, **kwargs: Any) -> Iterator[dict[str, Any]]:
        self._validate(operation)
        paginator = self._client.get_paginator(operation)
        yield from paginator.paginate(**kwargs)

    def _validate(self, operation: str) -> None:
        if operation not in ALLOWED_OPERATIONS.get(self.service_name, set()):
            raise UnsafeAwsOperationError(
                f"{self.service_name}:{operation} is not approved for read-only scanning"
            )
