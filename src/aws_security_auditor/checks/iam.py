from __future__ import annotations

from datetime import UTC, datetime, timedelta

from botocore.exceptions import BotoCoreError, ClientError

from aws_security_auditor.checks.base import CheckResult
from aws_security_auditor.models import Finding, ScanError, Severity
from aws_security_auditor.readonly_client import ReadOnlyAwsClient


def scan_iam(iam: ReadOnlyAwsClient, access_key_age_days: int) -> CheckResult:
    result = CheckResult(checks=7)
    cutoff = datetime.now(UTC) - timedelta(days=access_key_age_days)
    try:
        summary = iam.call("get_account_summary").get("SummaryMap", {})
        if summary.get("AccountMFAEnabled") != 1:
            result.findings.append(
                Finding(
                    Severity.HIGH,
                    "IAM_ROOT_MFA_DISABLED",
                    "IAM",
                    "global",
                    "root",
                    "Root account MFA is not enabled",
                    "The AWS account root user does not have MFA enabled.",
                    "Enable MFA for the root user.",
                )
            )
        if summary.get("AccountAccessKeysPresent", 0) > 0:
            result.findings.append(
                Finding(
                    Severity.HIGH,
                    "IAM_ROOT_ACCESS_KEYS_PRESENT",
                    "IAM",
                    "global",
                    "root",
                    "Root account access keys exist",
                    "The AWS account root user has access keys.",
                    "Delete root access keys and use IAM roles or users instead.",
                )
            )
        _password_policy_findings(iam, result)
        _administrator_access_findings(iam, result)

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


def _administrator_access_findings(iam: ReadOnlyAwsClient, result: CheckResult) -> None:
    for page in iam.paginate("get_account_authorization_details"):
        for user in page.get("UserDetailList", []):
            if _has_administrator_access(user):
                result.findings.append(
                    Finding(
                        Severity.HIGH,
                        "IAM_USER_ADMINISTRATOR_ACCESS",
                        "IAM",
                        "global",
                        user.get("UserName", "unknown"),
                        "IAM user has AdministratorAccess",
                        "IAM user has the AWS managed AdministratorAccess policy attached.",
                        "Prefer short-lived role access and remove direct administrator access.",
                    )
                )
        for group in page.get("GroupDetailList", []):
            if _has_administrator_access(group):
                result.findings.append(
                    Finding(
                        Severity.MEDIUM,
                        "IAM_GROUP_ADMINISTRATOR_ACCESS",
                        "IAM",
                        "global",
                        group.get("GroupName", "unknown"),
                        "IAM group has AdministratorAccess",
                        "IAM group has the AWS managed AdministratorAccess policy attached.",
                        "Review group membership and restrict administrator access.",
                    )
                )
        for role in page.get("RoleDetailList", []):
            if _has_administrator_access(role):
                result.findings.append(
                    Finding(
                        Severity.MEDIUM,
                        "IAM_ROLE_ADMINISTRATOR_ACCESS",
                        "IAM",
                        "global",
                        role.get("RoleName", "unknown"),
                        "IAM role has AdministratorAccess",
                        "IAM role has the AWS managed AdministratorAccess policy attached.",
                        "Review trust policy and restrict administrator access where possible.",
                    )
                )


def _has_administrator_access(detail: dict[str, object]) -> bool:
    policies = detail.get("AttachedManagedPolicies", [])
    if not isinstance(policies, list):
        return False
    return any(
        policy.get("PolicyName") == "AdministratorAccess"
        or str(policy.get("PolicyArn", "")).endswith("/AdministratorAccess")
        for policy in policies
        if isinstance(policy, dict)
    )


def _password_policy_findings(iam: ReadOnlyAwsClient, result: CheckResult) -> None:
    try:
        policy = iam.call("get_account_password_policy").get("PasswordPolicy", {})
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            result.findings.append(
                Finding(
                    Severity.MEDIUM,
                    "IAM_PASSWORD_POLICY_MISSING",
                    "IAM",
                    "global",
                    "account",
                    "IAM account password policy is missing",
                    "No IAM password policy is configured.",
                    "Configure a strong IAM account password policy.",
                )
            )
            return
        raise
    minimum_length = int(policy.get("MinimumPasswordLength", 0))
    if (
        minimum_length < 14
        or policy.get("RequireSymbols") is not True
        or policy.get("RequireNumbers") is not True
        or policy.get("RequireUppercaseCharacters") is not True
        or policy.get("RequireLowercaseCharacters") is not True
    ):
        result.findings.append(
            Finding(
                Severity.MEDIUM,
                "IAM_WEAK_PASSWORD_POLICY",
                "IAM",
                "global",
                "account",
                "IAM password policy is weak",
                "Password policy does not require length >= 14 plus symbols, numbers, "
                "uppercase, and lowercase characters.",
                "Strengthen the IAM account password policy.",
            )
        )


def _has_console_login(iam: ReadOnlyAwsClient, user_name: str) -> bool:
    try:
        iam.call("get_login_profile", UserName=user_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return False
        raise
    return True
