"""The Tier 4 equivalent of the in-cluster responder's Falco-health and
capability checks: proving the cross-account trust relationship in a
given AWS account actually works, rather than assuming it does because
Terraform applied cleanly once. This is the only thing in the whole
containment system that can verify this -- the in-cluster responder has
no AWS access at all, by design (see the containment build plan's
architecture).
"""

from __future__ import annotations

import logging

from .assume_role import assumed_role_session

logger = logging.getLogger("golem.iam_responder")


def check_account_coverage(sts_client, account_id: str, role_template: str) -> str:
    """Assumes into `account_id` and makes one minimal, harmless IAM read
    call to confirm the assumed session actually has IAM access -- not
    just that STS accepted the assumption (a role can be assumable but
    still carry a trust/permission policy that grants nothing useful,
    which a bare AssumeRole success wouldn't catch). Returns "verified" or
    "failed", never raises -- one broken account's trust relationship
    must not take down the sweep for every other account."""
    try:
        assume_role_arn = role_template.format(account_id=account_id)
        session = assumed_role_session(sts_client, assume_role_arn, f"golem-coverage-check-{account_id}")
        iam_client = session.client("iam")
        # list_account_aliases() is a minimal, always-available IAM read
        # with no prerequisites (no specific role/user needs to exist) --
        # it exists here solely to confirm "this assumed session can
        # actually call IAM", not because the alias itself matters.
        iam_client.list_account_aliases(MaxItems=1)
        return "verified"
    except Exception:
        logger.exception("Account coverage check failed for %s", account_id)
        return "failed"
