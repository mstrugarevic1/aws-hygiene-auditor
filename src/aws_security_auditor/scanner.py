from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace

from botocore.exceptions import BotoCoreError, ClientError

from aws_security_auditor.auth import build_session, client
from aws_security_auditor.checks.account import (
    scan_cloudtrail,
    scan_config,
    scan_guardduty,
    scan_securityhub,
)
from aws_security_auditor.checks.base import CheckResult
from aws_security_auditor.checks.ec2 import scan_ec2
from aws_security_auditor.checks.iam import scan_iam
from aws_security_auditor.checks.network import scan_ecr, scan_elbv2, scan_kms
from aws_security_auditor.checks.rds import scan_rds
from aws_security_auditor.checks.s3 import scan_s3
from aws_security_auditor.checks.tags import scan_regional_tags
from aws_security_auditor.config import DEFAULT_SERVICES, ScanConfig
from aws_security_auditor.models import (
    SEVERITY_ORDER,
    ScanError,
    ScanReport,
    ScanSummary,
    Severity,
    sort_findings,
)
from aws_security_auditor.regions import discover_regions

REGIONAL_SERVICES = {
    "cloudtrail",
    "config",
    "ec2",
    "ecr",
    "elbv2",
    "guardduty",
    "kms",
    "rds",
    "securityhub",
    "tags",
}


def run_scan(config: ScanConfig) -> ScanReport:
    started = time.monotonic()
    session = build_session(config)
    identity = client(session, "sts").call("get_caller_identity")
    account_id = identity.get("Account", "unknown")
    arn = identity.get("Arn", "unknown")
    if any(_enabled(config, service) for service in REGIONAL_SERVICES):
        regions, skipped = discover_regions(session, config.regions)
        excluded = set(config.exclude_regions)
        regions = [region for region in regions if region not in excluded]
    else:
        regions, skipped = [], []

    results: list[CheckResult] = []
    if config.verbose:
        results.append(
            CheckResult(errors=[ScanError("Region", r, "Skipped: not opted in") for r in skipped])
        )

    if _enabled(config, "s3"):
        results.append(scan_s3(session, client(session, "s3", "us-east-1"), account_id))
    if _enabled(config, "iam"):
        results.append(scan_iam(client(session, "iam", "us-east-1"), config.access_key_age_days))

    with ThreadPoolExecutor(max_workers=max(1, config.max_workers)) as pool:
        futures = {
            pool.submit(_scan_region, session, region, account_id, config): region
            for region in regions
        }
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except (ClientError, BotoCoreError, RuntimeError) as exc:
                results.append(
                    CheckResult(errors=[ScanError("Regional", futures[future], str(exc))])
                )

    findings = [finding for result in results for finding in result.findings]
    if config.severity:
        minimum = Severity(config.severity.upper())
        findings = [
            f for f in findings if SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[minimum]
        ]
    errors = [error for result in results for error in result.errors]
    summary = ScanSummary(
        scanned_regions=len(regions),
        checks_executed=sum(result.checks for result in results),
        resources_inspected=sum(result.resources for result in results),
        errors=len(errors),
        duration_seconds=round(time.monotonic() - started, 1),
    )
    return ScanReport(
        account_id,
        arn,
        config.profile,
        config.role_arn,
        regions,
        sort_findings(findings),
        errors,
        summary,
    )


def _scan_region(session: object, region: str, account_id: str, config: ScanConfig) -> CheckResult:
    combined = CheckResult()
    results: list[CheckResult] = []
    if _enabled(config, "cloudtrail"):
        results.append(scan_cloudtrail(client(session, "cloudtrail", region), region))
    if _enabled(config, "config"):
        results.append(scan_config(client(session, "config", region), region))
    if _enabled(config, "guardduty"):
        results.append(scan_guardduty(client(session, "guardduty", region), region))
    if _enabled(config, "securityhub"):
        results.append(scan_securityhub(client(session, "securityhub", region), region))
    if _enabled(config, "ec2"):
        results.append(
            scan_ec2(client(session, "ec2", region), region, account_id, config.snapshot_age_days)
        )
    if _enabled(config, "elbv2"):
        results.append(scan_elbv2(client(session, "elbv2", region), region))
    if _enabled(config, "ecr"):
        results.append(scan_ecr(client(session, "ecr", region), region))
    if _enabled(config, "kms"):
        results.append(scan_kms(client(session, "kms", region), region))
    if _enabled(config, "rds"):
        results.append(scan_rds(client(session, "rds", region), region))
    if _enabled(config, "tags"):
        results.append(
            scan_regional_tags(
                client(session, "ec2", region),
                client(session, "rds", region),
                region,
                config.required_tags,
            )
        )
    for result in results:
        combined = replace(
            combined,
            findings=combined.findings + result.findings,
            errors=combined.errors + result.errors,
            resources=combined.resources + result.resources,
            checks=combined.checks + result.checks,
        )
    return combined


def _enabled(config: ScanConfig, service: str) -> bool:
    services = DEFAULT_SERVICES if config.services is None else config.services
    return service in services
