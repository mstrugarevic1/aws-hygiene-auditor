from __future__ import annotations

from datetime import UTC, datetime, timedelta

from botocore.exceptions import ClientError

from aws_hygiene_auditor.checks.iam import scan_iam


class FakeIam:
    def paginate(self, operation: str, **kwargs: object):
        old = datetime.now(UTC) - timedelta(days=120)
        if operation == "list_users":
            return iter([[{"Users": [{"UserName": "alice", "CreateDate": old}]}][0]])
        if operation == "list_access_keys":
            return iter(
                [
                    [
                        {
                            "AccessKeyMetadata": [
                                {"AccessKeyId": "AKIAOLD", "Status": "Active", "CreateDate": old}
                            ]
                        }
                    ][0]
                ]
            )
        if operation == "list_mfa_devices":
            return iter([{"MFADevices": []}])
        if operation == "list_user_policies":
            return iter([{"PolicyNames": ["inline"]}])
        raise AssertionError(operation)

    def call(self, operation: str, **kwargs: object) -> dict[str, object]:
        if operation == "get_login_profile":
            return {"LoginProfile": {}}
        if operation == "get_access_key_last_used":
            return {"AccessKeyLastUsed": {}}
        raise ClientError({"Error": {"Code": "NoSuchEntity"}}, operation)


def test_old_access_key_and_missing_mfa() -> None:
    result = scan_iam(FakeIam(), 90)  # type: ignore[arg-type]
    assert {"IAM_OLD_ACCESS_KEY", "IAM_UNUSED_ACCESS_KEY", "IAM_USER_NO_MFA"} <= {
        f.check_id for f in result.findings
    }
