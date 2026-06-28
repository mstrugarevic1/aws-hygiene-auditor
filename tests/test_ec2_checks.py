from __future__ import annotations

from datetime import UTC, datetime

from botocore.exceptions import ClientError

from aws_security_auditor.checks.ec2 import scan_ec2


class FakeEc2:
    def call(self, operation: str, **kwargs: object) -> dict[str, object]:
        if operation == "get_ebs_encryption_by_default":
            return {"EbsEncryptionByDefault": False}
        if operation == "describe_snapshot_attribute":
            return {"CreateVolumePermissions": [{"Group": "all"}]}
        raise AssertionError(operation)

    def paginate(self, operation: str, **kwargs: object):
        old_snapshot = {
            "SnapshotId": "snap-1",
            "StartTime": datetime.now(UTC),
        }
        pages = {
            "describe_security_groups": [
                {
                    "SecurityGroups": [
                        {
                            "GroupId": "sg-1",
                            "GroupName": "default",
                            "IpPermissions": [
                                {
                                    "IpProtocol": "tcp",
                                    "FromPort": 22,
                                    "ToPort": 22,
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                },
                                {
                                    "IpProtocol": "tcp",
                                    "FromPort": 3389,
                                    "ToPort": 3389,
                                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                                },
                            ],
                        },
                        {
                            "GroupId": "sg-2",
                            "GroupName": "app",
                            "IpPermissions": [
                                {
                                    "IpProtocol": "tcp",
                                    "FromPort": 22,
                                    "ToPort": 22,
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                },
                                {
                                    "IpProtocol": "tcp",
                                    "FromPort": 3389,
                                    "ToPort": 3389,
                                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                                },
                                {
                                    "IpProtocol": "tcp",
                                    "FromPort": 80,
                                    "ToPort": 80,
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                },
                                {
                                    "IpProtocol": "tcp",
                                    "FromPort": 443,
                                    "ToPort": 443,
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                },
                            ],
                        },
                    ]
                }
            ],
            "describe_addresses": [[{"Addresses": [{"AllocationId": "eipalloc-1"}]}][0]],
            "describe_volumes": [
                {
                    "Volumes": [
                        {
                            "VolumeId": "vol-1",
                            "State": "available",
                            "Encrypted": False,
                            "Size": 8,
                            "CreateTime": datetime.now(UTC),
                        }
                    ]
                }
            ],
            "describe_snapshots": [{"Snapshots": [old_snapshot]}],
            "describe_images": [{"Images": [{"ImageId": "ami-1", "Public": True}]}],
        }
        return iter(pages[operation])


def test_ec2_findings() -> None:
    result = scan_ec2(FakeEc2(), "us-east-1", "123", 90)  # type: ignore[arg-type]
    check_ids = {f.check_id for f in result.findings}
    assert {
        "EC2_SG_OPEN_SSH",
        "EC2_SG_OPEN_RDP",
        "EC2_SG_OPEN_HTTP",
        "EC2_SG_OPEN_HTTPS",
        "EC2_UNUSED_EIP",
        "EBS_UNATTACHED_VOLUME",
        "EBS_UNENCRYPTED_VOLUME",
        "EBS_DEFAULT_ENCRYPTION_DISABLED",
        "EBS_PUBLIC_SNAPSHOT",
        "EC2_PUBLIC_AMI",
        "EC2_DEFAULT_SG_PUBLIC_INGRESS",
    } <= check_ids


class FakeEc2EbsFailure(FakeEc2):
    def call(self, operation: str, **kwargs: object) -> dict[str, object]:
        if operation == "get_ebs_encryption_by_default":
            raise ClientError(
                {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}},
                operation,
            )
        return super().call(operation, **kwargs)


def test_ec2_continues_security_group_scan_after_ebs_error() -> None:
    result = scan_ec2(FakeEc2EbsFailure(), "us-east-1", "123", 90)  # type: ignore[arg-type]
    check_ids = {f.check_id for f in result.findings}

    assert "EC2_SG_OPEN_SSH" in check_ids
    assert result.errors
