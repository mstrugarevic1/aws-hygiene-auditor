from __future__ import annotations

import pytest

from aws_security_auditor.readonly_client import (
    ALLOWED_OPERATIONS,
    ReadOnlyAwsClient,
    UnsafeAwsOperationError,
)


class FakeClient:
    called = False

    def delete_volume(self, **kwargs: object) -> None:
        self.called = True


def test_mutating_operation_rejected_locally() -> None:
    fake = FakeClient()
    client = ReadOnlyAwsClient("ec2", fake)

    with pytest.raises(UnsafeAwsOperationError):
        client.call("delete_volume", VolumeId="vol-1")

    assert fake.called is False


def test_source_has_no_prohibited_boto3_method_names() -> None:
    prohibited = (
        "create",
        "delete",
        "update",
        "modify",
        "put",
        "start",
        "stop",
        "terminate",
        "attach",
        "detach",
        "authorize",
        "revoke",
        "associate",
        "disassociate",
        "enable",
        "disable",
        "tag",
        "untag",
    )
    operations = {
        operation
        for allowed in ALLOWED_OPERATIONS.values()
        for operation in allowed
        if operation != "assume_role"
    }
    assert not [
        operation
        for operation in operations
        if any(part in operation.split("_") for part in prohibited)
    ]


def test_elbv2_service_name_is_boto3_name() -> None:
    assert "elbv2" in ALLOWED_OPERATIONS
    assert "elasticloadbalancingv2" not in ALLOWED_OPERATIONS
