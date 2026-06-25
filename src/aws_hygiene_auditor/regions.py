from __future__ import annotations

import boto3

from aws_hygiene_auditor.auth import client

ENABLED_STATUSES = {"opt-in-not-required", "opted-in"}


def discover_regions(
    session: boto3.Session,
    requested: tuple[str, ...] | None = None,
) -> tuple[list[str], list[str]]:
    ec2 = client(session, "ec2", "us-east-1")
    response = ec2.call("describe_regions", AllRegions=True)
    known = {
        r["RegionName"]: r.get("OptInStatus", "opt-in-not-required")
        for r in response.get("Regions", [])
        if r.get("RegionName")
    }
    enabled = sorted(name for name, status in known.items() if status in ENABLED_STATUSES)
    skipped = sorted(name for name, status in known.items() if status == "not-opted-in")
    if not requested:
        return enabled, skipped

    missing = [r for r in requested if r not in known]
    disabled = [r for r in requested if known.get(r) not in ENABLED_STATUSES and r in known]
    if missing or disabled:
        pieces = []
        if missing:
            pieces.append(f"unknown: {', '.join(missing)}")
        if disabled:
            pieces.append(f"not enabled: {', '.join(disabled)}")
        raise ValueError("Invalid region selection (" + "; ".join(pieces) + ")")
    return list(requested), skipped
