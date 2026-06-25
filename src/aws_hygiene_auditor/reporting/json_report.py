from __future__ import annotations

import json
from dataclasses import asdict

from aws_hygiene_auditor.models import ScanReport


def render_json(report: ScanReport) -> str:
    return json.dumps(
        {
            "account_id": report.account_id,
            "arn": report.arn,
            "profile": report.profile,
            "assumed_role": report.assumed_role,
            "regions": report.regions,
            "findings": [f.to_dict() for f in report.findings],
            "errors": [e.to_dict() for e in report.errors],
            "summary": asdict(report.summary),
        },
        indent=2,
        sort_keys=True,
        default=str,
    )
