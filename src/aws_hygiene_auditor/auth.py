from __future__ import annotations

from typing import Any

import boto3
from botocore.credentials import ReadOnlyCredentials

from aws_hygiene_auditor.config import AWS_CONFIG, ScanConfig
from aws_hygiene_auditor.readonly_client import ReadOnlyAwsClient


def build_session(config: ScanConfig) -> boto3.Session:
    session = boto3.Session(profile_name=config.profile) if config.profile else boto3.Session()
    if not config.role_arn:
        return session

    sts = ReadOnlyAwsClient("sts", session.client("sts", config=AWS_CONFIG))
    params: dict[str, Any] = {
        "RoleArn": config.role_arn,
        "RoleSessionName": "aws-hygiene-auditor",
    }
    if config.external_id:
        params["ExternalId"] = config.external_id
    creds = sts.call("assume_role", **params)["Credentials"]
    frozen = ReadOnlyCredentials(
        creds["AccessKeyId"],
        creds["SecretAccessKey"],
        creds["SessionToken"],
    )
    return boto3.Session(
        aws_access_key_id=frozen.access_key,
        aws_secret_access_key=frozen.secret_key,
        aws_session_token=frozen.token,
    )


def client(session: boto3.Session, service: str, region: str | None = None) -> ReadOnlyAwsClient:
    return ReadOnlyAwsClient(
        service, session.client(service, region_name=region, config=AWS_CONFIG)
    )
