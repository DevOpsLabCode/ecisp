import json

import boto3
import httpx
import pytest
from moto import mock_aws

from app.aws_actions import DENY_ALL_POLICY_NAME
from app.backend_client import GolemBackendClient
from app.responder import DEFAULT_ROLE_TEMPLATE, process_once


@pytest.fixture
def moto_accounts():
    """A real (moto-mocked) IAM role in the "target" account, plus a
    responder role moto lets any caller assume -- assumed_role_session
    doesn't need a matching trust policy for moto's STS mock to permit
    the assumption, but creating both roles for real, and asserting
    against the real target role's policies afterward, is what actually
    proves the responder's AWS calls do the right thing rather than just
    not crashing."""
    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        trust_policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}],
            }
        )
        iam.create_role(RoleName="golem-iam-responder", AssumeRolePolicyDocument=trust_policy)
        iam.create_role(RoleName="my-workload-role", AssumeRolePolicyDocument=trust_policy)
        yield iam


def _backend_with_commands(commands: list[dict], status_calls: list[tuple[str, str]]) -> GolemBackendClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=commands)
        # POST .../status
        command_id = request.url.path.rsplit("/", 2)[1]
        body = json.loads(request.content)
        status_calls.append((command_id, body["status"]))
        return httpx.Response(204)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    return GolemBackendClient("https://golem.example.com", "test-key", http_client=http_client)


def test_process_once_applies_a_role_resolved_command(moto_accounts):
    status_calls: list[tuple[str, str]] = []
    commands = [
        {
            "id": "cmd-1",
            "status": "role_resolved",
            "resolved_role_arn": "arn:aws:iam::123456789012:role/my-workload-role",
        }
    ]
    backend = _backend_with_commands(commands, status_calls)
    sts = boto3.client("sts", region_name="us-east-1")

    processed = process_once(backend, sts, role_template="arn:aws:iam::{account_id}:role/golem-iam-responder")

    assert processed == 1
    assert status_calls == [("cmd-1", "applied")]
    policy = moto_accounts.get_role_policy(RoleName="my-workload-role", PolicyName=DENY_ALL_POLICY_NAME)
    assert policy["PolicyDocument"]["Statement"][0]["Effect"] == "Deny"


def test_process_once_releases_a_release_pending_command(moto_accounts):
    # Apply first (as a real prior cycle would have), then verify release
    # actually removes the policy.
    status_calls: list[tuple[str, str]] = []
    role_arn = "arn:aws:iam::123456789012:role/my-workload-role"
    apply_backend = _backend_with_commands(
        [{"id": "cmd-1", "status": "role_resolved", "resolved_role_arn": role_arn}], []
    )
    sts = boto3.client("sts", region_name="us-east-1")
    process_once(apply_backend, sts, role_template="arn:aws:iam::{account_id}:role/golem-iam-responder")

    release_backend = _backend_with_commands(
        [{"id": "cmd-1", "status": "release_pending", "resolved_role_arn": role_arn}], status_calls
    )
    processed = process_once(release_backend, sts, role_template="arn:aws:iam::{account_id}:role/golem-iam-responder")

    assert processed == 1
    assert status_calls == [("cmd-1", "released")]
    remaining = moto_accounts.list_role_policies(RoleName="my-workload-role")["PolicyNames"]
    assert remaining == []


def test_process_once_reports_failed_for_an_invalid_role_arn(moto_accounts):
    status_calls: list[tuple[str, str]] = []
    commands = [{"id": "cmd-1", "status": "role_resolved", "resolved_role_arn": "not-a-real-arn"}]
    backend = _backend_with_commands(commands, status_calls)
    sts = boto3.client("sts", region_name="us-east-1")

    process_once(backend, sts, role_template=DEFAULT_ROLE_TEMPLATE)

    assert status_calls == [("cmd-1", "failed")]


def test_process_once_reports_failed_when_the_target_role_does_not_exist(moto_accounts):
    status_calls: list[tuple[str, str]] = []
    commands = [
        {
            "id": "cmd-1",
            "status": "role_resolved",
            "resolved_role_arn": "arn:aws:iam::123456789012:role/does-not-exist",
        }
    ]
    backend = _backend_with_commands(commands, status_calls)
    sts = boto3.client("sts", region_name="us-east-1")

    process_once(backend, sts, role_template="arn:aws:iam::{account_id}:role/golem-iam-responder")

    assert status_calls == [("cmd-1", "failed")]


def test_process_once_handles_multiple_commands_independently(moto_accounts):
    status_calls: list[tuple[str, str]] = []
    commands = [
        {
            "id": "cmd-good",
            "status": "role_resolved",
            "resolved_role_arn": "arn:aws:iam::123456789012:role/my-workload-role",
        },
        {"id": "cmd-bad", "status": "role_resolved", "resolved_role_arn": "not-a-real-arn"},
    ]
    backend = _backend_with_commands(commands, status_calls)
    sts = boto3.client("sts", region_name="us-east-1")

    processed = process_once(backend, sts, role_template="arn:aws:iam::{account_id}:role/golem-iam-responder")

    assert processed == 2
    assert ("cmd-good", "applied") in status_calls
    assert ("cmd-bad", "failed") in status_calls


def test_process_once_with_no_commands_does_nothing(moto_accounts):
    backend = _backend_with_commands([], [])
    sts = boto3.client("sts", region_name="us-east-1")

    processed = process_once(backend, sts, role_template=DEFAULT_ROLE_TEMPLATE)

    assert processed == 0
