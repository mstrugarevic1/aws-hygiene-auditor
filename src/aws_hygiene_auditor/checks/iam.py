from __future__ import annotations

from datetime import UTC, datetime, timedelta

from botocore.exceptions import BotoCoreError, ClientError

from aws_hygiene_auditor.checks.base import CheckResult
from aws_hygiene_auditor.models import Finding, ScanError, Severity
from aws_hygiene_auditor.readonly_client import ReadOnlyAwsClient


def scan_iam(iam: ReadOnlyAwsClient, access_key_age_days: int) -> CheckResult:
    result = CheckResult(checks=4)
    cutoff = datetime.now(UTC) - timedelta(days=access_key_age_days)
    try:
        for page in iam.paginate("list_users"):
            users = page.get("Users", [])
            result.resources += len(users)
            for user in users:
                name = user.get("UserName", "unknown")
                has_console = _has_console_login(iam, name)
                mfa_devices = [
                    device
                    for mfa_page in iam.paginate("list_mfa_devices", UserName=name)
                    for device in mfa_page.get("MFADevices", [])
                ]
                if has_console and not mfa_devices:
                    result.findings.append(
                        Finding(
                            Severity.HIGH,
                            "IAM_USER_NO_MFA",
                            "IAM",
                            "global",
                            name,
                            "Console user without MFA",
                            "IAM user has no MFA devices configured.",
                            "Require MFA for console users.",
                        )
                    )
                policy_names = [
                    policy
                    for policy_page in iam.paginate("list_user_policies", UserName=name)
                    for policy in policy_page.get("PolicyNames", [])
                ]
                if policy_names:
                    result.findings.append(
                        Finding(
                            Severity.LOW,
                            "IAM_DIRECT_INLINE_USER_POLICY",
                            "IAM",
                            "global",
                            name,
                            "User has directly assigned inline policies",
                            "IAM user has inline policies assigned directly instead of "
                            "through groups or roles.",
                            "Prefer group-based policy assignment.",
                        )
                    )
                for key_page in iam.paginate("list_access_keys", UserName=name):
                    keys = key_page.get("AccessKeyMetadata", [])
                    result.resources += len(keys)
                    for key in keys:
                        created = key.get("CreateDate")
                        key_id = key.get("AccessKeyId", "unknown")
                        if (
                            key.get("Status") == "Active"
                            and isinstance(created, datetime)
                            and created < cutoff
                        ):
                            result.findings.append(
                                Finding(
                                    Severity.HIGH,
                                    "IAM_OLD_ACCESS_KEY",
                                    "IAM",
                                    "global",
                                    key_id,
                                    "Active access key older than threshold",
                                    f"Active access key is older than {access_key_age_days} days.",
                                    "Rotate or remove old access keys.",
                                )
                            )
                        last_used = iam.call("get_access_key_last_used", AccessKeyId=key_id).get(
                            "AccessKeyLastUsed", {}
                        )
                        last = last_used.get("LastUsedDate")
                        if last is None and isinstance(created, datetime) and created < cutoff:
                            result.findings.append(
                                Finding(
                                    Severity.MEDIUM,
                                    "IAM_UNUSED_ACCESS_KEY",
                                    "IAM",
                                    "global",
                                    key_id,
                                    "Unused access key older than threshold",
                                    "Access key has no last-used date and is older than "
                                    f"{access_key_age_days} days.",
                                    "Remove unused access keys.",
                                )
                            )
                        elif isinstance(last, datetime) and last < cutoff:
                            result.findings.append(
                                Finding(
                                    Severity.MEDIUM,
                                    "IAM_UNUSED_ACCESS_KEY",
                                    "IAM",
                                    "global",
                                    key_id,
                                    "Access key unused beyond threshold",
                                    f"Access key has not been used in {access_key_age_days} days.",
                                    "Remove or rotate unused access keys.",
                                )
                            )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        return CheckResult(errors=[ScanError("IAM", "global", f"IAM scan skipped: {exc}")])
    return result


def _has_console_login(iam: ReadOnlyAwsClient, user_name: str) -> bool:
    try:
        iam.call("get_login_profile", UserName=user_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return False
        raise
    return True
