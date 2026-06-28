from __future__ import annotations

import csv
from io import StringIO

from aws_security_auditor.models import ScanReport


def render_csv(report: ScanReport) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "severity",
            "region",
            "service",
            "resource_id",
            "check_id",
            "title",
            "description",
            "recommendation",
        ],
    )
    writer.writeheader()
    for finding in report.findings:
        writer.writerow(finding.to_dict())
    return output.getvalue()
