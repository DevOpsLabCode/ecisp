"""Shape captured from a real Falco alert: a local `kind` cluster running
the real Falco Helm chart (driver.kind=modern_ebpf) + falcosidekick,
attacking a real pod (`cat /etc/shadow` inside a container) and capturing
the exact JSON falcosidekick POSTed to a throwaway webhook receiver. See
falco_ingest.py's docstring for the full story.
"""

import pytest

from app.runtimedefender.falco_ingest import MalformedFalcoAlert, parse_falco_alert

_REAL_FALCO_ALERT = {
    "uuid": "a63c8f17-21f2-49ea-a225-05d0e93f13a0",
    "output": (
        "16:23:00.782994107: Warning Sensitive file opened for reading by non-trusted program | "
        "file=/etc/shadow gparent=<NA> ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 "
        "user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=<NA> command=cat /etc/shadow "
        "terminal=0 container_id=e50187cce4e6 container_name=test-victim "
        "container_image_repository=docker.io/library/alpine container_image_tag=3.18 "
        "k8s_pod_name=test-victim k8s_ns_name=default"
    ),
    "priority": "Warning",
    "rule": "Read sensitive file untrusted",
    "time": "2026-08-20T16:23:00.782994107Z",
    "output_fields": {
        "container.id": "e50187cce4e6",
        "container.image.repository": "docker.io/library/alpine",
        "container.image.tag": "3.18",
        "container.name": "test-victim",
        "evt.time": 1787242980782994107,
        "evt.type": "open",
        "fd.name": "/etc/shadow",
        "k8s.ns.name": "default",
        "k8s.pod.name": "test-victim",
        "proc.cmdline": "cat /etc/shadow",
        "proc.exepath": "/bin/busybox",
        "proc.name": "cat",
        "proc.tty": 0,
        "user.loginuid": -1,
        "user.name": "root",
        "user.uid": 0,
    },
    "source": "syscall",
    "tags": ["", "T1555", "container", "filesystem", "host", "maturity_stable", "mitre_credential_access"],
    "hostname": "ecisp-defender-test-control-plane",
}


def test_parse_falco_alert_extracts_a_real_finding():
    alert = parse_falco_alert(_REAL_FALCO_ALERT, cluster_label="kind-test-cluster")

    assert alert.finding.repository == "kind-test-cluster"
    assert alert.finding.file == "default/test-victim/test-victim"
    assert alert.finding.scanner == "falco"
    assert alert.finding.rule_id == "Read sensitive file untrusted"
    assert alert.finding.severity == "medium"  # Warning -> medium
    assert alert.finding.category == "runtime"
    assert "cat /etc/shadow" in alert.finding.message

    assert alert.image_ref == "docker.io/library/alpine:3.18"
    assert alert.pod_name == "test-victim"
    assert alert.namespace == "default"
    assert alert.mitre_techniques == ["T1555"]


@pytest.mark.parametrize(
    "priority,expected",
    [
        ("Emergency", "critical"),
        ("Alert", "critical"),
        ("Critical", "critical"),
        ("Error", "high"),
        ("Warning", "medium"),
        ("Notice", "low"),
        ("Informational", "info"),
        ("Debug", "info"),
        ("SomeUnknownLevel", "medium"),  # unrecognized priority falls back to medium, not a crash
    ],
)
def test_priority_severity_mapping(priority, expected):
    payload = {**_REAL_FALCO_ALERT, "priority": priority}
    alert = parse_falco_alert(payload, cluster_label="c")
    assert alert.finding.severity == expected


def test_parse_falco_alert_handles_missing_output_fields():
    payload = {"rule": "Some rule", "priority": "Notice", "output": "some output text"}
    alert = parse_falco_alert(payload, cluster_label="my-cluster")
    assert alert.finding.file == "my-cluster"  # falls back to the cluster label
    assert alert.image_ref is None
    assert alert.pod_name is None
    assert alert.namespace is None
    assert alert.mitre_techniques == []


def test_parse_falco_alert_falls_back_when_image_tag_missing():
    payload = {
        "rule": "Some rule",
        "priority": "Notice",
        "output": "some output text",
        "output_fields": {"container.image.repository": "alpine"},
    }
    alert = parse_falco_alert(payload, cluster_label="c")
    assert alert.image_ref == "alpine"


@pytest.mark.parametrize("missing_field", ["rule", "priority", "output"])
def test_parse_falco_alert_rejects_payloads_missing_required_fields(missing_field):
    payload = {**_REAL_FALCO_ALERT}
    del payload[missing_field]
    with pytest.raises(MalformedFalcoAlert):
        parse_falco_alert(payload, cluster_label="c")


def test_parse_falco_alert_rejects_empty_payload():
    with pytest.raises(MalformedFalcoAlert):
        parse_falco_alert({}, cluster_label="c")
