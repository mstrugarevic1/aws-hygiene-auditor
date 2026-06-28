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
from aws_security_auditor.config import ScanConfig
from aws_security_auditor.models import ScanError, ScanReport, ScanSummary, Severity, sort_findings
from aws_security_auditor.regions import discover_regions


def run_scan(config: ScanConfig) -> ScanReport:
    started = time.monotonic()
    session = build_session(config)
    identity = client(session, "sts").call("get_caller_identity")
    account_id = identity.get("Account", "unknown")
    arn = identity.get("Arn", "unknown")
    regions, skipped = discover_regions(session, config.regions)

    results: list[CheckResult] = []
    if config.verbose:
        results.append(
            CheckResult(errors=[ScanError("Region", r, "Skipped: not opted in") for r in skipped])
        )

    results.append(scan_s3(session, client(session, "s3", "us-east-1"), account_id))
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
        minimum = Severity(config.severity)
        findings = [f for f in findings if f.severity == minimum]
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
    ec2 = client(session, "ec2", region)
    rds = client(session, "rds", region)
    combined = CheckResult()
    for result in (
        scan_cloudtrail(client(session, "cloudtrail", region), region),
        scan_config(client(session, "config", region), region),
        scan_guardduty(client(session, "guardduty", region), region),
        scan_securityhub(client(session, "securityhub", region), region),
        scan_ec2(ec2, region, account_id, config.snapshot_age_days),
        scan_elbv2(client(session, "elbv2", region), region),
        scan_ecr(client(session, "ecr", region), region),
        scan_kms(client(session, "kms", region), region),
        scan_rds(rds, region),
        scan_regional_tags(ec2, rds, region, config.required_tags),
    ):
        combined = replace(
            combined,
            findings=combined.findings + result.findings,
            errors=combined.errors + result.errors,
            resources=combined.resources + result.resources,
            checks=combined.checks + result.checks,
        )
    return combined
