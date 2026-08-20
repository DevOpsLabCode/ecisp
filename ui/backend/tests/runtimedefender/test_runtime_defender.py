import pytest

from app.runtimedefender.falco_ingest import MalformedFalcoAlert
from app.runtimedefender.runtime_defender import (
    ClusterNotFound,
    InvalidInstallToken,
    RuntimeDefenderManager,
)

_REAL_ALERT_PAYLOAD = {
    "rule": "Read sensitive file untrusted",
    "priority": "Warning",
    "output": "16:23:00... command=cat /etc/shadow ...",
    "output_fields": {
        "container.image.repository": "docker.io/library/alpine",
        "container.image.tag": "3.18",
        "container.name": "test-victim",
        "k8s.ns.name": "default",
        "k8s.pod.name": "test-victim",
    },
    "tags": ["T1555", "container"],
}


@pytest.fixture
def manager():
    return RuntimeDefenderManager()


def test_create_cluster_generates_a_unique_token(manager):
    c1 = manager.create_cluster("cluster-a")
    c2 = manager.create_cluster("cluster-b")
    assert c1.install_token != c2.install_token
    assert c1.id != c2.id


def test_new_cluster_has_zeroed_summary(manager):
    cluster = manager.create_cluster("cluster-a")
    summary = cluster.summary()
    assert summary["finding_count"] == 0
    assert summary["severity_counts"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    assert summary["last_event_at"] is None


def test_ingest_event_appends_a_finding_and_updates_last_event_at(manager):
    cluster = manager.create_cluster("cluster-a")
    finding = manager.ingest_event(cluster.id, cluster.install_token, _REAL_ALERT_PAYLOAD)

    assert finding.rule_id == "Read sensitive file untrusted"
    assert finding.severity == "medium"
    assert len(cluster.findings) == 1
    assert cluster.last_event_at is not None
    assert cluster.summary()["finding_count"] == 1
    assert cluster.summary()["severity_counts"]["medium"] == 1


def test_ingest_event_raises_for_unknown_cluster(manager):
    with pytest.raises(ClusterNotFound):
        manager.ingest_event("does-not-exist", "any-token", _REAL_ALERT_PAYLOAD)


def test_ingest_event_raises_for_wrong_token(manager):
    cluster = manager.create_cluster("cluster-a")
    with pytest.raises(InvalidInstallToken):
        manager.ingest_event(cluster.id, "wrong-token", _REAL_ALERT_PAYLOAD)


def test_ingest_event_raises_for_malformed_payload(manager):
    cluster = manager.create_cluster("cluster-a")
    with pytest.raises(MalformedFalcoAlert):
        manager.ingest_event(cluster.id, cluster.install_token, {"not": "a falco alert"})


def test_ingest_event_appends_a_registry_scan_correlation_note_when_one_is_found(manager, monkeypatch):
    import app.runtimedefender.runtime_defender as module

    monkeypatch.setattr(
        module,
        "correlate_image_with_registry_scans",
        lambda image_ref: f"correlated: {image_ref} has known CVEs",
    )
    cluster = manager.create_cluster("cluster-a")
    finding = manager.ingest_event(cluster.id, cluster.install_token, _REAL_ALERT_PAYLOAD)

    assert "correlated: docker.io/library/alpine:3.18 has known CVEs" in finding.remediation
    # The base remediation text should still be present alongside the note.
    assert "Investigate the process/command" in finding.remediation


def test_ingest_event_leaves_remediation_unchanged_when_no_correlation_found(manager, monkeypatch):
    import app.runtimedefender.runtime_defender as module

    monkeypatch.setattr(module, "correlate_image_with_registry_scans", lambda image_ref: None)
    cluster = manager.create_cluster("cluster-a")
    finding = manager.ingest_event(cluster.id, cluster.install_token, _REAL_ALERT_PAYLOAD)

    assert finding.remediation is not None
    assert "\n\n" not in finding.remediation


def test_findings_list_is_capped_at_max_size(manager, monkeypatch):
    import app.runtimedefender.runtime_defender as module

    monkeypatch.setattr(module, "MAX_FINDINGS_PER_CLUSTER", 3)
    cluster = manager.create_cluster("cluster-a")
    for _ in range(5):
        manager.ingest_event(cluster.id, cluster.install_token, _REAL_ALERT_PAYLOAD)

    assert len(cluster.findings) == 3


def test_detail_includes_install_token_and_findings(manager):
    cluster = manager.create_cluster("cluster-a")
    manager.ingest_event(cluster.id, cluster.install_token, _REAL_ALERT_PAYLOAD)

    detail = cluster.detail()
    assert detail["install_token"] == cluster.install_token
    assert len(detail["findings"]) == 1


def test_as_repo_scan_result_reflects_accumulated_findings(manager):
    cluster = manager.create_cluster("cluster-a")
    manager.ingest_event(cluster.id, cluster.install_token, _REAL_ALERT_PAYLOAD)

    result = cluster.as_repo_scan_result()
    assert result.repository == "cluster-a"
    assert result.scanners_run == ["falco"]
    assert len(result.findings) == 1


def test_as_repo_scan_result_reports_no_scanners_run_with_no_findings(manager):
    cluster = manager.create_cluster("cluster-a")
    result = cluster.as_repo_scan_result()
    assert result.scanners_run == []


def test_list_and_get(manager):
    cluster = manager.create_cluster("cluster-a")
    assert manager.get(cluster.id) is cluster
    assert cluster in manager.list()


def test_get_returns_none_for_unknown_id(manager):
    assert manager.get("does-not-exist") is None


def test_list_orders_most_recently_created_first(manager):
    c1 = manager.create_cluster("first")
    c2 = manager.create_cluster("second")
    assert manager.list() == [c2, c1]
