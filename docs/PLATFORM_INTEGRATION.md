# Enterprise Cloud Discovery Engine — Platform Integration Specification

## Service boundary

Run the engine as an isolated worker. The orchestration service creates a discovery job and supplies a short-lived credential reference, provider scope, tenant ID, and output location. The worker returns a manifest plus normalized JSONL.

## Job request

```json
{
  "job_id": "disc-20260712-0001",
  "tenant_id": "tenant-001",
  "provider": "aws",
  "credential_ref": "vault://tenants/tenant-001/aws/audit-role",
  "scope": {"accounts": ["123456789012"], "regions": ["us-east-1"]},
  "services": ["iam", "ec2", "s3", "eks", "cloudtrail", "config"],
  "mode": "full",
  "output_uri": "s3://evidence/tenant-001/disc-20260712-0001/"
}
```

## Job result

```json
{
  "job_id": "disc-20260712-0001",
  "status": "completed_with_warnings",
  "resources_collected": 18422,
  "services_succeeded": 6,
  "services_failed": 1,
  "snapshot_uri": ".../native-snapshot.json",
  "normalized_uri": ".../evidence.jsonl",
  "manifest_uri": ".../manifest.json",
  "started_at": "...",
  "completed_at": "..."
}
```

## Canonical mappings

| Native discovery object | Canonical platform object | Correlation key |
|---|---|---|
| AWS account | `cloud_account` | account ID |
| Azure subscription | `cloud_account` | subscription ID |
| GCP project | `cloud_account` | project ID / number |
| Kubernetes cluster | `cluster` | provider ID + cluster UID |
| VM / instance | `compute_instance` | provider resource ID |
| Container image | `image` | digest, then registry/repository/tag |
| IAM principal | `identity` | provider principal ID / ARN |
| Network object | `network_asset` | provider resource ID |
| Storage resource | `storage_asset` | provider resource ID |
| Configuration finding | `control_result` | control ID + resource ID + snapshot |

## Failure semantics

- Authentication failure: fail job; no coverage conclusion.
- One service failure: retain successful services and mark snapshot partial.
- Region throttling: checkpoint and retry with jitter.
- Permission denied: emit `collection_gap` evidence, not a false pass.
- Empty result: distinguish confirmed-empty from uncollected.
- Stale snapshot: exclude from migration approval calculations.

## Deployment

Use a dedicated worker image with no inbound network port. Jobs are pulled from a queue. Raw provider responses go to encrypted object storage; normalized records go to the evidence ingestion API. The worker database is ephemeral.
