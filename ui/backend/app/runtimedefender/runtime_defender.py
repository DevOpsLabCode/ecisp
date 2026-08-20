"""Registers Kubernetes clusters running the Falco sensor (see
`falco_ingest.py`) and accumulates the runtime findings each one reports.

Deliberately **not** a job queue like `codescan.code_scan_job` /
`orgscan.org_scan_job` / `registryscan.registry_scan_job` -- those all
model "kick off one run, it eventually finishes." A cluster's Defender
install never finishes; it streams events for as long as it's deployed.
So this is a plain in-memory registry (`create` a cluster once, `ingest`
appends to it indefinitely) rather than a worker-thread queue, and reports
are generated on demand at download time from whatever findings have
accumulated so far, rather than written to disk after every single event --
writing all five formats (PDF included) on every incoming alert would be
real, wasted work during an actual incident, when Falco can emit many
events in quick succession.

One real cluster, covered end to end against this module's design: a local
`kind` cluster running the real Falco Helm chart + falcosidekick, attacking
a pod, and confirming the alert survives the full round trip through
`falco_ingest.parse_falco_alert` into a real `Finding`.
"""

from __future__ import annotations

import secrets
import threading
import uuid
from datetime import UTC, datetime

from ..orgscan.models import Finding, RepoScanResult
from .falco_ingest import MalformedFalcoAlert, parse_falco_alert
from .sca_correlation import correlate_image_with_registry_scans

# A single incident storm shouldn't be able to grow one cluster's finding
# list without bound -- keep the most recent MAX_FINDINGS and drop the
# oldest, same "cap it, don't let one bad day take down the process" idea
# as archive_extract.py's size caps serve for uploads.
MAX_FINDINGS_PER_CLUSTER = 5000


class ClusterNotFound(Exception):
    pass


class InvalidInstallToken(Exception):
    """The webhook caller's token doesn't match this cluster's -- either a
    typo'd install script, or someone probing the endpoint."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


class RuntimeCluster:
    def __init__(self, cluster_id: str, name: str):
        self.id = cluster_id
        self.name = name
        self.install_token = secrets.token_urlsafe(24)
        self.created_at = _now()
        self.last_event_at: str | None = None
        self.findings: list[Finding] = []
        self._lock = threading.Lock()

    def severity_counts(self) -> dict[str, int]:
        return RepoScanResult(
            repository=self.name, technologies=[], scanners_run=[], scanners_skipped={}, findings=self.findings
        ).severity_counts()

    def summary(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at,
            "last_event_at": self.last_event_at,
            "severity_counts": self.severity_counts(),
            "finding_count": len(self.findings),
        }

    def detail(self) -> dict:
        return {
            **self.summary(),
            "install_token": self.install_token,
            "findings": [f.to_dict() for f in self.findings],
        }

    def as_repo_scan_result(self) -> RepoScanResult:
        """Reuses the org-scan/code-scan report generators, which all take
        a `RepoScanResult` -- a cluster's accumulated findings fit that
        shape exactly, "repository" just means "this cluster" here."""
        return RepoScanResult(
            repository=self.name,
            technologies=["falco"],
            scanners_run=["falco"] if self.findings else [],
            scanners_skipped={},
            findings=self.findings,
        )


class RuntimeDefenderManager:
    def __init__(self):
        self._clusters: dict[str, RuntimeCluster] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()

    def create_cluster(self, name: str) -> RuntimeCluster:
        cluster = RuntimeCluster(uuid.uuid4().hex, name)
        with self._lock:
            self._clusters[cluster.id] = cluster
            self._order.insert(0, cluster.id)
        return cluster

    def get(self, cluster_id: str) -> RuntimeCluster | None:
        return self._clusters.get(cluster_id)

    def list(self) -> list[RuntimeCluster]:
        with self._lock:
            return [self._clusters[cid] for cid in self._order]

    def ingest_event(self, cluster_id: str, token: str, payload: dict) -> Finding:
        cluster = self._clusters.get(cluster_id)
        if cluster is None:
            raise ClusterNotFound(cluster_id)
        if not secrets.compare_digest(token, cluster.install_token):
            raise InvalidInstallToken("install token does not match this cluster")

        alert = parse_falco_alert(payload, cluster_label=cluster.name)
        correlation = correlate_image_with_registry_scans(alert.image_ref)
        if correlation:
            alert.finding.remediation = f"{alert.finding.remediation}\n\n{correlation}"
        with cluster._lock:
            cluster.findings.append(alert.finding)
            if len(cluster.findings) > MAX_FINDINGS_PER_CLUSTER:
                cluster.findings = cluster.findings[-MAX_FINDINGS_PER_CLUSTER:]
            cluster.last_event_at = _now()
        return alert.finding


manager = RuntimeDefenderManager()

__all__ = [
    "ClusterNotFound",
    "InvalidInstallToken",
    "MalformedFalcoAlert",
    "RuntimeCluster",
    "RuntimeDefenderManager",
    "manager",
]
