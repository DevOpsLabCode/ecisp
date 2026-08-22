"""The AWS side of Tier 4: assuming a role in the target account and
attaching/removing the explicit deny-all inline policy that actually
revokes a compromised workload's IAM permissions.

Every function here takes its AWS clients as arguments rather than
constructing its own -- keeps this module free of any global boto3
session, so tests can hand in clients bound to moto's mock AWS instead of
a real account, and the responder module (responder.py) controls exactly
when a fresh set of assumed-role credentials gets created.
"""

from __future__ import annotations

import json
import re

# An explicit Deny on every action/resource always wins over any Allow in
# IAM's evaluation logic (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html),
# regardless of what other policies attached to this role permit -- this
# is what actually revokes the role the instant it's attached, not just a
# detachment of specific permissions that might miss something.
DENY_ALL_POLICY_NAME = "golem-containment-deny-all"
DENY_ALL_POLICY_DOCUMENT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
    }
)

_ROLE_ARN_PATTERN = re.compile(r"^arn:aws:iam::(?P<account_id>\d{12}):role/(?P<path_and_name>.+)$")


class InvalidRoleArn(ValueError):
    """The string handed to parse_role_arn doesn't look like a real IAM
    role ARN -- e.g. the in-cluster responder resolved something that
    wasn't actually a role ARN, or a user role instead."""


def parse_role_arn(role_arn: str) -> tuple[str, str]:
    """Returns (account_id, role_name) from an IAM role ARN. A role ARN
    with a path (`arn:...:role/team/my-role`) still has just "my-role" as
    its actual RoleName -- IAM's PutRolePolicy/DeleteRolePolicy APIs want
    that bare name, not the full path+name string."""
    match = _ROLE_ARN_PATTERN.match(role_arn)
    if not match:
        raise InvalidRoleArn(f"not a valid IAM role ARN: {role_arn!r}")
    role_name = match.group("path_and_name").rsplit("/", 1)[-1]
    return match.group("account_id"), role_name


def build_assume_role_arn(account_id: str, role_template: str) -> str:
    """`role_template` is the per-account role this component assumes to
    act in that account, e.g. "arn:aws:iam::{account_id}:role/golem-iam-responder"
    -- see the README for the trust relationship that role needs."""
    return role_template.format(account_id=account_id)


def apply_deny_policy(iam_client, role_name: str) -> None:
    """Attaches the deny-all inline policy -- the actual revocation.
    Idempotent: PutRolePolicy overwrites a policy of the same name if one
    already exists, so calling this twice (e.g. on a retried command) is
    safe and produces the same end state."""
    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName=DENY_ALL_POLICY_NAME,
        PolicyDocument=DENY_ALL_POLICY_DOCUMENT,
    )


def remove_deny_policy(iam_client, role_name: str) -> None:
    """Removes the deny-all inline policy -- the human-triggered
    reversal. DeleteRolePolicy on a policy that doesn't exist raises
    NoSuchEntityException; callers that want removal to be idempotent
    (e.g. a retried release) should catch that specifically rather than
    treating every ClientError as a real failure."""
    iam_client.delete_role_policy(RoleName=role_name, PolicyName=DENY_ALL_POLICY_NAME)
