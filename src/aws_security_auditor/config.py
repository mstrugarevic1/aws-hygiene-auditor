from __future__ import annotations

from dataclasses import dataclass

from botocore.config import Config

DEFAULT_REQUIRED_TAGS = ("Owner", "Environment", "CostCenter")


@dataclass(frozen=True)
class ScanConfig:
    profile: str | None = None
    role_arn: str | None = None
    external_id: str | None = None
    regions: tuple[str, ...] | None = None
    output: str = "table"
    output_file: str | None = None
    severity: str | None = None
    fail_on: str | None = None
    no_color: bool = False
    verbose: bool = False
    snapshot_age_days: int = 90
    access_key_age_days: int = 90
    required_tags: tuple[str, ...] = DEFAULT_REQUIRED_TAGS
    max_workers: int = 5


AWS_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 5})
