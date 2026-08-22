import json

import boto3
import pytest
from moto import mock_aws

from app.assume_role import assumed_role_session


@pytest.fixture
def target_role_arn():
    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        role = iam.create_role(
            RoleName="golem-iam-responder",
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}],
                }
            ),
        )
        yield role["Role"]["Arn"]


def test_assumed_role_session_returns_a_session_bound_to_temporary_credentials(target_role_arn):
    with mock_aws():
        sts = boto3.client("sts", region_name="us-east-1")

        session = assumed_role_session(sts, target_role_arn, "golem-containment-cmd-1")

        creds = session.get_credentials()
        assert creds.access_key
        assert creds.secret_key
        assert creds.token


def test_assumed_role_session_can_build_a_service_client(target_role_arn):
    with mock_aws():
        sts = boto3.client("sts", region_name="us-east-1")

        session = assumed_role_session(sts, target_role_arn, "golem-containment-cmd-1")
        iam_client = session.client("iam", region_name="us-east-1")

        # Just confirms the client is real and usable -- listing roles in
        # the (empty, from this session's perspective) mocked account.
        response = iam_client.list_roles()
        assert "Roles" in response
