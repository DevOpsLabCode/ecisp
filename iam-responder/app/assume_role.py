"""Cross-account role assumption -- separated from aws_actions.py because
it's the one place this component talks to STS rather than IAM, and
because tests want to mock the assumption step and the deny-policy step
independently."""

from __future__ import annotations

import boto3


def assumed_role_session(sts_client, role_arn: str, session_name: str) -> boto3.Session:
    """Assumes `role_arn` (in the target AWS account) and returns a fresh
    boto3 Session bound to the temporary credentials -- callers build
    whatever service client they need (iam_client = session.client("iam"))
    from it. `session_name` shows up in that account's CloudTrail, so
    callers should pass something that ties back to the specific
    containment command, not a generic constant."""
    response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
    creds = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
