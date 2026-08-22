import json

import boto3
import pytest
from moto import mock_aws

from app.aws_actions import (
    DENY_ALL_POLICY_NAME,
    InvalidRoleArn,
    apply_deny_policy,
    build_assume_role_arn,
    parse_role_arn,
    remove_deny_policy,
)

# ---- parse_role_arn --------------------------------------------------


def test_parse_role_arn_extracts_account_and_role_name():
    account_id, role_name = parse_role_arn("arn:aws:iam::111111111111:role/my-workload-role")
    assert account_id == "111111111111"
    assert role_name == "my-workload-role"


def test_parse_role_arn_strips_a_path_down_to_the_bare_role_name():
    # PutRolePolicy/DeleteRolePolicy want just "my-role", not "team/my-role"
    account_id, role_name = parse_role_arn("arn:aws:iam::111111111111:role/team/my-role")
    assert account_id == "111111111111"
    assert role_name == "my-role"


def test_parse_role_arn_rejects_a_non_role_arn():
    with pytest.raises(InvalidRoleArn):
        parse_role_arn("arn:aws:iam::111111111111:user/not-a-role")


def test_parse_role_arn_rejects_garbage():
    with pytest.raises(InvalidRoleArn):
        parse_role_arn("not-an-arn-at-all")


# ---- build_assume_role_arn --------------------------------------------


def test_build_assume_role_arn_fills_in_the_account_id():
    arn = build_assume_role_arn("222222222222", "arn:aws:iam::{account_id}:role/golem-iam-responder")
    assert arn == "arn:aws:iam::222222222222:role/golem-iam-responder"


# ---- apply_deny_policy / remove_deny_policy, against real moto-mocked IAM ----


@pytest.fixture
def iam_client():
    with mock_aws():
        client = boto3.client("iam", region_name="us-east-1")
        client.create_role(
            RoleName="my-workload-role",
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}],
                }
            ),
        )
        yield client


def test_apply_deny_policy_attaches_an_explicit_deny_all_inline_policy(iam_client):
    apply_deny_policy(iam_client, "my-workload-role")

    policy = iam_client.get_role_policy(RoleName="my-workload-role", PolicyName=DENY_ALL_POLICY_NAME)
    document = policy["PolicyDocument"]
    assert document["Statement"][0]["Effect"] == "Deny"
    assert document["Statement"][0]["Action"] == "*"
    assert document["Statement"][0]["Resource"] == "*"


def test_apply_deny_policy_is_idempotent(iam_client):
    apply_deny_policy(iam_client, "my-workload-role")
    apply_deny_policy(iam_client, "my-workload-role")  # must not raise

    policies = iam_client.list_role_policies(RoleName="my-workload-role")["PolicyNames"]
    assert policies == [DENY_ALL_POLICY_NAME]


def test_remove_deny_policy_removes_it(iam_client):
    apply_deny_policy(iam_client, "my-workload-role")

    remove_deny_policy(iam_client, "my-workload-role")

    policies = iam_client.list_role_policies(RoleName="my-workload-role")["PolicyNames"]
    assert policies == []


def test_remove_deny_policy_raises_if_never_applied(iam_client):
    # Deliberately not swallowed here -- responder.py's caller decides how
    # to handle "nothing to release" (see its own tests).
    with pytest.raises(iam_client.exceptions.NoSuchEntityException):
        remove_deny_policy(iam_client, "my-workload-role")
