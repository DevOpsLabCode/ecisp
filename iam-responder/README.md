# Golem IAM Responder (Tier 4)

The privilege-isolated half of Golem Defender's containment response
ladder: the piece that actually revokes an AWS IAM role once the
in-cluster responder (`ui/backend/app/runtimedefender/responder_install_script.py`)
has resolved which role a compromised workload was using.

This is a **separate deployable process**, not a route inside `ui/backend`'s
FastAPI app -- deliberately. See the containment build plan's architecture:
the in-cluster responder (Kubernetes RBAC only, zero AWS access) and this
component (AWS credentials only, zero Kubernetes access) must never share a
credential, a process, or a network path to each other. A compromise of
either one must never be a path to the other's blast radius.

## What it does

Polls `GET /api/iam-revocation/commands` on the Golem backend -- a
fleet-wide, cross-cluster view authenticated with its own `IAM_RESPONDER_API_KEY`,
a completely different credential from any cluster's per-cluster install
token (see `ui/backend/app/main.py`). For each command:

- **`role_resolved`** (ready to apply): assumes a role in the target AWS
  account, attaches an explicit deny-all inline policy to the compromised
  role. IAM's evaluation logic means an explicit `Deny` always wins over
  any `Allow`, so this blocks every action for every principal using that
  role immediately, regardless of what else it's permitted to do.
- **`release_pending`** (an operator clicked Release in the dashboard):
  assumes the same way, removes the deny policy.

Reports `applied` / `released` / `failed` back to the same command via
`POST /api/iam-revocation/commands/{id}/status`.

## Cross-account assumption

Every monitored AWS account is expected to have a role this component can
assume -- by default `arn:aws:iam::<account-id>:golem-iam-responder`,
overridable via `GOLEM_ASSUME_ROLE_TEMPLATE` (must contain `{account_id}`).
That role needs, at minimum:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iam:PutRolePolicy", "iam:DeleteRolePolicy"],
      "Resource": "arn:aws:iam::*:role/golem-monitored-*"
    }
  ]
}
```

Scoping `Resource` to a naming convention (`golem-monitored-*`) rather than
`*` means this component -- even fully compromised -- can only ever touch
roles an operator has already opted into monitoring, not arbitrary IAM
roles in the account. Deciding on and provisioning that per-account trust
relationship (via Terraform, reusing the cross-account patterns already
established for `demand-gig-engine`) is separate follow-up work; nothing
in this repo sets it up automatically.

This component's *own* execution identity (however it's deployed -- ECS
task role, EKS pod IRSA role, etc.) needs `sts:AssumeRole` on
`arn:aws:iam::*:role/golem-iam-responder` and nothing else. It should run
in Golem's own security-tooling AWS account, separate from every
monitored account.

## Running it

```bash
pip install -r requirements.txt
export BACKEND_URL=https://golem.example.com
export IAM_RESPONDER_API_KEY=...          # matches the backend's own env var
export POLL_INTERVAL_SECONDS=10           # default
python -m app
```

Or via Docker:

```bash
docker build -t golem-iam-responder .
docker run --rm \
  -e BACKEND_URL=https://golem.example.com \
  -e IAM_RESPONDER_API_KEY=... \
  golem-iam-responder
```

No Kubernetes access of any kind is needed or requested -- this image has
no `kubectl`, no cluster credentials, nothing beyond `boto3` and an HTTP
client. AWS credentials are picked up the normal boto3 way (environment,
instance/task/pod role, `~/.aws/credentials`) -- never hardcoded, never
passed as a command-line argument.

## Testing

```bash
pip install -r requirements-test.txt
pytest
```

Every AWS interaction is tested against [moto](https://github.com/getmoto/moto),
which intercepts `boto3` calls and simulates the real AWS API surface --
this suite has never made a real AWS call and never will. No live
cross-account trust relationship exists yet in any real AWS account (see
above), so this component has not been exercised end to end against a
real account; moto verifies the logic (role assumption, the deny-policy
document, the resource-name parsing) is correct, not that a specific
account's trust policy is configured right.
