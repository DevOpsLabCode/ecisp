import json

import boto3
import pytest
from moto import mock_aws

from app.account_coverage import check_account_coverage


@pytest.fixture
def responder_role_arn():
    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        trust_policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}],
            }
        )
        role = iam.create_role(RoleName="golem-iam-responder", AssumeRolePolicyDocument=trust_policy)
        yield role["Role"]["Arn"]


def test_check_account_coverage_verified_when_assumable_and_iam_reachable(responder_role_arn):
    with mock_aws():
        sts = boto3.client("sts", region_name="us-east-1")

        status = check_account_coverage(sts, "123456789012", "arn:aws:iam::{account_id}:role/golem-iam-responder")

        assert status == "verified"


class _RaisingStsClient:
    """A stub, not moto -- moto's STS mock does not validate RoleArn
    format or role existence by default (confirmed empirically: it
    accepts a nonexistent role name and even a non-ARN-shaped string
    without complaint), so it can't produce a real "assumption failed"
    outcome the way a live AWS account would. This stub exercises exactly
    the contract that actually matters: check_account_coverage must
    convert *any* failure into "failed", never raise."""

    def assume_role(self, **_kwargs):
        raise RuntimeError("simulated AccessDenied assuming role")


def test_check_account_coverage_failed_when_assume_role_fails():
    status = check_account_coverage(
        _RaisingStsClient(), "999999999999", "arn:aws:iam::{account_id}:role/golem-iam-responder"
    )

    assert status == "failed"


def test_check_account_coverage_never_raises_on_a_malformed_template():
    # A template referencing a placeholder other than {account_id} is a
    # caller bug (str.format raises KeyError) -- not something that
    # should crash the whole sweep for every other account.
    status = check_account_coverage(_RaisingStsClient(), "123456789012", "arn:aws:iam::{wrong_key}:role/x")

    assert status == "failed"
