from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_hygiene_auditor.auth import client
from aws_hygiene_auditor.checks.base import CheckResult
from aws_hygiene_auditor.models import Finding, ScanError, Severity
from aws_hygiene_auditor.readonly_client import ReadOnlyAwsClient


def bucket_region(s3: ReadOnlyAwsClient, bucket: str) -> str:
    response = s3.call("get_bucket_location", Bucket=bucket)
    return response.get("LocationConstraint") or "us-east-1"


def scan_s3(session: Any, account_s3: ReadOnlyAwsClient, account_id: str) -> CheckResult:
    result = CheckResult(checks=6)
    try:
        buckets = account_s3.call("list_buckets").get("Buckets", [])
    except (ClientError, BotoCoreError) as exc:
        return CheckResult(
            errors=[ScanError("S3", "global", f"S3 bucket enumeration skipped: {exc}")]
        )

    result.resources += len(buckets)
    s3control = client(session, "s3control", "us-east-1")
    account_public_block_disabled = _account_public_block_disabled(s3control, account_id)
    for bucket_info in buckets:
        bucket = bucket_info.get("Name")
        if not bucket:
            continue
        try:
            region = bucket_region(account_s3, bucket)
            s3 = client(session, "s3", region)
            result.findings.extend(
                _bucket_findings(s3, bucket, region, account_public_block_disabled)
            )
        except (ClientError, BotoCoreError, KeyError, TypeError, json.JSONDecodeError) as exc:
            result.errors.append(ScanError("S3", "global", f"{bucket} skipped: {exc}"))
    return result


def _account_public_block_disabled(s3control: ReadOnlyAwsClient, account_id: str) -> bool:
    try:
        cfg = s3control.call("get_public_access_block", AccountId=account_id).get(
            "PublicAccessBlockConfiguration", {}
        )
    except ClientError:
        return True
    return not all(
        cfg.get(k) is True
        for k in (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )
    )


def _bucket_findings(
    s3: ReadOnlyAwsClient,
    bucket: str,
    region: str,
    account_public_block_disabled: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    if _acl_public(s3, bucket):
        findings.append(
            _finding(Severity.HIGH, "S3_PUBLIC_ACL", region, bucket, "Public S3 bucket ACL")
        )
    if _policy_public(s3, bucket):
        findings.append(
            _finding(Severity.HIGH, "S3_PUBLIC_POLICY", region, bucket, "Public S3 bucket policy")
        )
    if account_public_block_disabled or _bucket_public_block_disabled(s3, bucket):
        findings.append(
            _finding(
                Severity.MEDIUM,
                "S3_PUBLIC_ACCESS_BLOCK_DISABLED",
                region,
                bucket,
                "S3 public access block disabled",
            )
        )
    if _missing(s3, bucket, "get_bucket_encryption"):
        findings.append(
            _finding(
                Severity.MEDIUM,
                "S3_DEFAULT_ENCRYPTION_MISSING",
                region,
                bucket,
                "S3 encryption missing",
            )
        )
    if s3.call("get_bucket_versioning", Bucket=bucket).get("Status") != "Enabled":
        findings.append(
            _finding(
                Severity.LOW, "S3_VERSIONING_DISABLED", region, bucket, "S3 versioning disabled"
            )
        )
    if "LoggingEnabled" not in s3.call("get_bucket_logging", Bucket=bucket):
        findings.append(
            _finding(
                Severity.LOW,
                "S3_ACCESS_LOGGING_DISABLED",
                region,
                bucket,
                "S3 access logging disabled",
            )
        )
    return findings


def _finding(severity: Severity, check_id: str, region: str, bucket: str, title: str) -> Finding:
    return Finding(
        severity,
        check_id,
        "S3",
        region,
        bucket,
        title,
        title,
        "Review bucket configuration and restrict public access unless explicitly required.",
    )


def _acl_public(s3: ReadOnlyAwsClient, bucket: str) -> bool:
    try:
        grants = s3.call("get_bucket_acl", Bucket=bucket).get("Grants", [])
    except ClientError:
        return False
    return any(
        g.get("Grantee", {}).get("URI", "").endswith(("AllUsers", "AuthenticatedUsers"))
        for g in grants
    )


def _policy_public(s3: ReadOnlyAwsClient, bucket: str) -> bool:
    try:
        status = s3.call("get_bucket_policy_status", Bucket=bucket)
        if status.get("PolicyStatus", {}).get("IsPublic") is True:
            return True
        policy = json.loads(s3.call("get_bucket_policy", Bucket=bucket).get("Policy", "{}"))
    except ClientError:
        return False
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return any(s.get("Effect") == "Allow" and s.get("Principal") == "*" for s in statements)


def _bucket_public_block_disabled(s3: ReadOnlyAwsClient, bucket: str) -> bool:
    try:
        cfg = s3.call("get_bucket_public_access_block", Bucket=bucket).get(
            "PublicAccessBlockConfiguration", {}
        )
    except ClientError:
        return True
    return not all(
        cfg.get(k) is True
        for k in (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )
    )


def _missing(s3: ReadOnlyAwsClient, bucket: str, operation: str) -> bool:
    try:
        s3.call(operation, Bucket=bucket)
    except ClientError:
        return True
    return False
