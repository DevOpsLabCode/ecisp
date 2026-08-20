"""Parses a Falco alert (delivered via falcosidekick's `webhook` output) into
this app's shared `Finding` model -- the runtime-detection equivalent of
`orgscan.normalize.parse_sarif`, just for Falco's own JSON shape rather than
SARIF, since falcosidekick's webhook payload isn't SARIF.

Verified against a real payload: a local `kind` cluster running the real
Falco Helm chart (`driver.kind=modern_ebpf`, no kernel module needed) with
falcosidekick's webhook output pointed at a throwaway HTTP listener,
attacking a real pod (`cat /etc/shadow` inside a container) and capturing
the exact JSON falcosidekick POSTs:

    {
      "uuid": "...", "rule": "Read sensitive file untrusted",
      "priority": "Warning", "output": "16:23:00... command=cat /etc/shadow ...",
      "time": "2026-08-20T16:23:00.782994107Z",
      "output_fields": {
        "container.image.repository": "docker.io/library/alpine",
        "container.image.tag": "3.18", "container.name": "test-victim",
        "k8s.ns.name": "default", "k8s.pod.name": "test-victim", ...
      },
      "tags": ["T1555", "container", "filesystem", "mitre_credential_access", ...],
      "hostname": "..."
    }

The `container.image.repository`/`.tag` fields are exactly the hook a
"this CVE is running right now" correlation with code-scan/registry-scan
results would key off of later -- captured here as `image_ref` even though
nothing correlates on it yet.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..orgscan.models import Finding

# Falco's eight syslog-style priority levels, collapsed onto this app's five
# severities. Emergency/Alert/Critical are all "critical" in practice --
# Falco's own default ruleset barely uses anything above Critical.
_PRIORITY_TO_SEVERITY = {
    "emergency": "critical",
    "alert": "critical",
    "critical": "critical",
    "error": "high",
    "warning": "medium",
    "notice": "low",
    "informational": "info",
    "debug": "info",
}


class MalformedFalcoAlert(ValueError):
    """The webhook body isn't a recognizable Falco/falcosidekick alert."""


@dataclass
class RuntimeAlert:
    finding: Finding
    image_ref: str | None
    pod_name: str | None
    namespace: str | None
    mitre_techniques: list[str]


def _severity_for(priority: str) -> str:
    return _PRIORITY_TO_SEVERITY.get(priority.strip().lower(), "medium")


def parse_falco_alert(payload: dict, cluster_label: str) -> RuntimeAlert:
    """Raises `MalformedFalcoAlert` if the payload is missing the fields
    every real Falco alert has (`rule`, `priority`, `output`)."""
    rule = payload.get("rule")
    priority = payload.get("priority")
    output = payload.get("output")
    if not rule or not priority or not output:
        raise MalformedFalcoAlert("payload is missing rule/priority/output -- not a Falco alert")

    fields = payload.get("output_fields") or {}
    pod_name = fields.get("k8s.pod.name")
    namespace = fields.get("k8s.ns.name")
    container_name = fields.get("container.name")
    image_repo = fields.get("container.image.repository")
    image_tag = fields.get("container.image.tag")
    image_ref = f"{image_repo}:{image_tag}" if image_repo and image_tag else image_repo

    location = "/".join(p for p in (namespace, pod_name, container_name) if p) or cluster_label
    tags = payload.get("tags") or []
    mitre = [t for t in tags if isinstance(t, str) and t.upper().startswith("T") and t[1:].replace(".", "").isdigit()]

    finding = Finding(
        repository=cluster_label,
        file=location,
        scanner="falco",
        rule_id=rule,
        severity=_severity_for(priority),
        category="runtime",
        message=output,
        remediation="Investigate the process/command in the alert message. If this is expected behavior "
        "(e.g. a legitimate admin task), add a Falco exception rule rather than ignoring the alert class "
        "entirely -- narrow exceptions keep the signal useful for real incidents.",
    )
    return RuntimeAlert(
        finding=finding,
        image_ref=image_ref,
        pod_name=pod_name,
        namespace=namespace,
        mitre_techniques=mitre,
    )
