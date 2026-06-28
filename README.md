# aws-security-auditor

<p align="center">
  <img src="docs/assets/aws-security-auditor-logo.jpg" alt="AWS Security Auditor logo" width="320">
</p>

<p align="center">
  <a href="https://github.com/mstrugarevic1/aws-hygiene-auditor/actions/workflows/test.yml"><img alt="Tests" src="https://github.com/mstrugarevic1/aws-hygiene-auditor/actions/workflows/test.yml/badge.svg"></a>
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
python -m pip install -e ".[dev]"
```

## Usage

```bash
aws-security-auditor scan
aws-security-auditor scan --profile production-readonly --output table
aws-security-auditor scan --output json --output-file report.json
```

Options:

```text
--profile PROFILE
--role-arn ROLE_ARN
--external-id EXTERNAL_ID
--regions REGION1,REGION2
--output table|json|markdown
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

- EC2 security groups open to the world for SSH, RDP, database ports, all ports, or other non-web ports
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
HIGH    eu-central-1 (Europe (Frankfurt))  EC2  sg-012345   SSH open to the world
MEDIUM  eu-west-1 (Europe (Ireland))       EBS  vol-012345  Unattached EBS volume
LOW     us-east-1 (US East (N. Virginia))  EC2  i-012345    Missing required tags

Scanned regions: 18
Checks executed: 12
Resources inspected: 247
HIGH: 2
MEDIUM: 7
LOW: 14
Errors: 1
Duration: 12.4s
```

JSON and Markdown reports contain no ANSI color codes.

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
