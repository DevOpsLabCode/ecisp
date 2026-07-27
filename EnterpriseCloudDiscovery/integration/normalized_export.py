"""Convert provider discovery output into the platform evidence envelope."""
from __future__ import annotations
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "1.0"


def evidence_record(provider: str, resource_type: str, source_id: str,
                    payload: dict[str, Any], tenant_id: str,
                    account_id: str | None = None,
                    region: str | None = None) -> dict[str, Any]:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    observed_at = datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "source": "enterprise-cloud-discovery-engine",
        "provider": provider,
        "resource_type": resource_type,
        "source_id": source_id,
        "account_id": account_id,
        "region": region,
        "observed_at": observed_at,
        "payload_sha256": sha256(canonical.encode()).hexdigest(),
        "payload": payload,
    }


def write_jsonl(records: Iterable[dict[str, Any]], output: str | Path) -> int:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, default=str) + "\n")
            count += 1
    return count
