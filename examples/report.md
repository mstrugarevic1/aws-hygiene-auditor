# AWS Security Auditor Report

| Field | Value |
| --- | --- |
| Account | `123456789012` |
| ARN | `arn:aws:iam::123456789012:role/AwsSecurityAuditorReadOnly` |
| Regions scanned | 2 |

| Severity | Region | Service | Resource | Finding |
| --- | --- | --- | --- | --- |
| HIGH | eu-central-1 (Europe (Frankfurt)) | EC2 | sg-012345 | SSH open to the world |

## Summary

| Metric | Value |
| --- | --- |
| Scanned regions | 2 |
| Checks executed | 12 |
| Resources inspected | 42 |
| HIGH | 1 |
| MEDIUM | 0 |
| LOW | 0 |
| Errors | 0 |
| Duration | 3.2s |
