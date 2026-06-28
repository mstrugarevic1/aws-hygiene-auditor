# aws-security-auditor

<p align="center">
  <img src="docs/assets/aws-security-auditor-logo-transparent.png" alt="AWS Security Auditor logo" width="384">
</p>

<p align="center">
  <a href="https://github.com/mstrugarevic1/aws-security-auditor/actions/workflows/test.yml"><img alt="Tests" src="https://github.com/mstrugarevic1/aws-security-auditor/actions/workflows/test.yml/badge.svg"></a>
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-blue">
  <img alt="pytest" src="https://img.shields.io/badge/tests-pytest-green">
  <img alt="License MIT" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="AI assisted with Codex" src="https://img.shields.io/badge/AI_assisted-Codex-111827">
</p>

`aws-security-auditor` is a small Python CLI that scans an AWS account for common security,
cost, and governance posture issues.

This tool never modifies AWS resources. It performs only read-only List, Get and Describe
operations and can be used with a read-only IAM role.

This tool is not a replacement for AWS Security Hub, AWS Config, CloudTrail, Trusted Advisor,
Prowler, or a formal security assessment. It is a point-in-time read-only scanner for quick
account reviews.

## Install

Requires Python 3.11+.

```bash
git clone https://github.com/mstrugarevic1/aws-security-auditor.git
cd aws-security-auditor
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

For local development:

```bash
python -m pip install -e ".[dev]"
```

## Usage

```bash
aws-security-auditor scan --profile audit
aws-security-auditor scan --profile audit --regions eu-central-1,eu-west-1
aws-security-auditor scan --profile audit --exclude-regions us-east-1
aws-security-auditor scan --profile audit --services ec2,s3,iam
aws-security-auditor scan --profile audit --severity MEDIUM
aws-security-auditor scan --output json --output-file report.json
aws-security-auditor scan --output csv --output-file findings.csv
```

Options:

```text
--profile PROFILE
--role-arn ROLE_ARN
--external-id EXTERNAL_ID
--regions REGION1,REGION2
--exclude-regions REGION1,REGION2
--services ec2,s3,iam
--output table|json|markdown|csv
--output-file PATH
--severity HIGH|MEDIUM|LOW
--fail-on HIGH|MEDIUM|LOW
--no-color
--verbose
--snapshot-age-days 90
--access-key-age-days 90
--required-tags Owner,Environment,CostCenter
--max-workers 5
```

By default the scanner discovers all enabled AWS regions with `ec2:DescribeRegions`. It scans
`opt-in-not-required` and `opted-in` regions, and skips `not-opted-in` regions. IAM, STS, and
S3 bucket enumeration run once as global/account-level checks.

Use `--services` to scan only selected services. Supported values are `cloudtrail`, `config`,
`ec2`, `ecr`, `elbv2`, `guardduty`, `iam`, `kms`, `rds`, `s3`, `securityhub`, and `tags`.

Use `--severity MEDIUM` to show `HIGH` and `MEDIUM` findings. Use `--severity HIGH` to show only
high-severity findings.

Use `--fail-on HIGH` in CI or scheduled jobs when high-severity findings should fail the run.

## Authentication

Supported authentication:

- default boto3 credential chain
- named AWS profile
- optional STS AssumeRole

Recommended approach: use a dedicated read-only role.

```bash
aws-security-auditor scan \
  --role-arn arn:aws:iam::123456789012:role/AwsSecurityAuditorReadOnly
```

Example trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
      "Action": "sts:AssumeRole"
    }
  ]
}
```

The tool does not require administrator permissions. Some checks may be skipped when the role
lacks access to specific services.

Before scanning it calls `sts:GetCallerIdentity` and displays the account ID, ARN, selected
profile or assumed role, and region count. It never prints credentials, tokens, or secrets.

## Checks

Severity meanings:

- `HIGH`: likely security exposure requiring prompt review
- `MEDIUM`: cost, resilience, or exposure issue worth fixing
- `LOW`: governance or security posture improvement

Implemented checks:

- EC2 security groups open to the world for SSH, RDP, HTTP, HTTPS, database ports, all ports, or other ports
- default security groups with public ingress
- unused Elastic IP addresses
- unattached or unencrypted EBS volumes, and disabled EBS encryption by default
- old account-owned EBS snapshots
- public account-owned AMIs and public EBS snapshots
- public, unencrypted, under-backed-up RDS instances
- S3 public ACL/policy, public access block, encryption, versioning, and access logging
- IAM root MFA, root access keys, password policy, old or unused access keys, console users without MFA, direct inline user policies
- CloudTrail trails, AWS Config recorders, GuardDuty detectors, and Security Hub enablement
- internet-facing Application/Network Load Balancers
- ECR scan-on-push settings
- KMS key rotation for eligible customer-managed keys
- missing required tags on EC2 instances, EBS volumes, and RDS instances

## How this differs from AWS native services

- CloudTrail records AWS API activity and is used for audit and incident investigation.
- AWS Config records resource configuration history and evaluates compliance rules continuously.
- Security Hub aggregates security findings and posture controls across accounts and services.
- This tool gives a fast read-only snapshot without enabling a managed service first.

## Example Output

```text
+----------+--------------------------+---------+-----------+-------------------------------+
| Severity | Region                   | Service | Resource  | Finding                       |
+----------+--------------------------+---------+-----------+-------------------------------+
| HIGH     | global                   | IAM     | root      | Root account MFA is disabled  |
| HIGH     | eu-central-1 (Frankfurt) | EC2     | sg-012345 | SSH open to the world         |
| MEDIUM   | eu-west-1 (Ireland)      | Config  | account   | Config recorder is missing    |
| LOW      | us-east-1 (N. Virginia)  | ECR     | app       | ECR scan on push is disabled  |
+----------+--------------------------+---------+-----------+-------------------------------+

Scanned regions: 18
Checks executed: 28
Resources inspected: 413
HIGH: 4
MEDIUM: 6
LOW: 3
Errors: 1
Duration: 12.4s
```

With `--fail-on HIGH`, the report is still rendered, but the command exits with status `1`
when at least one `HIGH` finding is present.

JSON and Markdown reports contain no ANSI color codes.
CSV reports contain one row per finding.

## Safety

All AWS calls pass through a local read-only client wrapper with an explicit operation allowlist.
If code tries to call an unapproved operation such as `delete_volume` or `stop_instances`, the
wrapper raises before boto3 is called. There is no remediation mode and no `--fix`, `--delete`,
or cleanup flag.

## Limitations

- It checks common security posture issues only.
- It does not inspect S3 objects or object contents.
- It does not remediate findings.
- IAM direct managed policy attachment checks are intentionally omitted because the AWS API name
  contains `Attach`, which this project blocks by policy.
- API errors are reported and the scan continues where possible.

## Development

```bash
ruff check .
mypy src
pytest
```

CI runs those commands without AWS credentials and without integration tests against a real account.

## License

MIT. See [LICENSE](LICENSE).
