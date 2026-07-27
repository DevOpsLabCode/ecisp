# Enterprise Cloud Discovery Engine

A read-only multi-cloud discovery and configuration-evidence component integrated into the **Enterprise Cloud Security Discovery, Reporting & Migration Platform**.

## Platform role

This engine is the **cloud-source discovery layer**. It collects provider-native inventory and configuration facts, then passes normalized evidence to the platform. It does not replace the Prisma, Cortex, or Wiz connectors and it does not execute migrations.

## Supported discovery providers

- AWS
- Microsoft Azure
- Google Cloud
- Kubernetes
- Oracle Cloud Infrastructure
- DigitalOcean
- Alibaba Cloud

## Integration flow

```text
Provider APIs
    -> Enterprise Cloud Discovery Engine
    -> Provider-native snapshot
    -> Normalized evidence envelope
    -> Evidence repository
    -> Asset correlation graph
    -> Coverage delta and onboarding validation
    -> Executive / engineering reporting
```

## Repository placement

```text
enterprise-cloud-security-platform/
  src/
    discovery/
      cloud_engine/                 # this package
        EnterpriseCloudDiscovery/
        tests/
        requirements.txt
        setup.py
    connectors/
      prisma/
      cortex/
      wiz/
    normalize/
    correlate/
    validation/
    reporting/
    evidence/
```

## New package and command names

- Python package: `EnterpriseCloudDiscovery`
- Distribution: `enterprise-cloud-discovery-engine`
- CLI: `enterprise-cloud-discovery`
- Platform command: `enterprise-cloud discover`
- Evidence source key: `enterprise-cloud-discovery-engine`

## Exact platform contract

Each normalized record contains:

```json
{
  "schema_version": "1.0",
  "tenant_id": "tenant-001",
  "source": "enterprise-cloud-discovery-engine",
  "provider": "aws",
  "resource_type": "ec2_instance",
  "source_id": "i-0123456789abcdef0",
  "account_id": "123456789012",
  "region": "us-east-1",
  "observed_at": "2026-07-12T14:00:00+00:00",
  "payload_sha256": "...",
  "payload": {}
}
```

## Integration responsibilities

### Discovery engine owns

- Provider authentication and API enumeration
- Service/resource inventory
- Native configuration collection
- Read-only configuration checks
- Provider-native snapshot generation
- Source timestamps and evidence checksums

### Platform core owns

- Tenant isolation
- Scheduling and job orchestration
- Central secrets retrieval
- Normalization into canonical asset models
- Correlation with Prisma, Cortex, Wiz, repositories, registries, CI/CD and owners
- Coverage delta analysis
- Migration readiness and execution gates
- Dashboards, exports and evidence retention

## Execution stages

1. `authenticate` — validate read-only credentials.
2. `enumerate` — discover accounts, subscriptions, projects, regions and clusters.
3. `collect` — gather service inventories and configuration facts.
4. `snapshot` — store immutable provider-native output.
5. `normalize` — emit one evidence envelope per resource.
6. `ingest` — submit JSONL records to the platform evidence service.
7. `correlate` — connect resources to vendor security coverage and ownership.
8. `validate` — calculate freshness, completeness and onboarding gaps.

## Production changes still required

- Replace direct filesystem report assumptions with an `EvidenceSink` interface.
- Move credential loading behind the platform `CredentialProvider` interface.
- Add scheduler job IDs, tenant IDs and correlation IDs to every log event.
- Add incremental checkpoints per provider/account/region/service.
- Add bounded concurrency and centralized rate-limit budgets.
- Add dead-letter handling for partially failed service collection.
- Add canonical resource adapters under `normalize/providers/`.
- Add PostgreSQL/object-storage sinks for production scale; SQLite remains supported for local demos.
- Add contract tests against saved API fixtures for every provider.
- Add software bill of materials, dependency scanning and signed release artifacts.

## Security boundaries

- Discovery is read-only by default.
- Migration/write permissions are prohibited in discovery credentials.
- Raw snapshots may contain sensitive metadata and must be encrypted at rest.
- Secrets must never be written to logs, HTML, JSON snapshots or SQLite.
- Every run must record tenant, principal, provider scope, start/end time and checksum manifest.

## Local installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
enterprise-cloud-discovery --help
```

## Maintainer

Maintained by **DevOps Lab Inc.**  
Contact: **hello@devopslabinc.com**  
Website: **https://devopslabinc.com**

## Licensing

This modified component remains licensed under GPLv2. Preserve `LICENSE` and `THIRD_PARTY_NOTICES.md` when distributing source or binaries. Platform services that must remain independently licensed should communicate with this component through a process or API boundary and should receive legal review before distribution.
