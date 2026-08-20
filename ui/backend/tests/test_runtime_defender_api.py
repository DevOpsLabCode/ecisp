import pytest
from fastapi.testclient import TestClient

from app import main
from app.main import app
from app.runtimedefender.runtime_defender import RuntimeDefenderManager

client = TestClient(app)

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
def isolated_manager(monkeypatch):
    fresh = RuntimeDefenderManager()
    monkeypatch.setattr(main, "runtime_defender_manager", fresh)
    return fresh


def test_create_cluster_rejects_an_empty_name(isolated_manager):
    resp = client.post("/api/runtime-clusters", json={"name": "  "})
    assert resp.status_code == 400


def test_create_cluster_returns_an_install_token(isolated_manager):
    resp = client.post("/api/runtime-clusters", json={"name": "prod-eks"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "prod-eks"
    assert body["install_token"]
    assert body["finding_count"] == 0


def test_list_clusters(isolated_manager):
    client.post("/api/runtime-clusters", json={"name": "cluster-a"})
    resp = client.get("/api/runtime-clusters")
    assert resp.status_code == 200
    assert any(c["name"] == "cluster-a" for c in resp.json())


def test_get_cluster_404_for_unknown_id(isolated_manager):
    resp = client.get("/api/runtime-clusters/does-not-exist")
    assert resp.status_code == 404


def test_get_install_script_embeds_the_real_webhook_url(isolated_manager):
    create_resp = client.post("/api/runtime-clusters", json={"name": "prod-eks"})
    cluster_id = create_resp.json()["id"]
    token = create_resp.json()["install_token"]

    resp = client.get(f"/api/runtime-clusters/{cluster_id}/install.sh")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/x-shellscript")
    assert f"/api/runtime-clusters/{cluster_id}/events?token={token}" in resp.text
    assert "helm upgrade --install falco" in resp.text


def test_get_install_script_404_for_unknown_cluster(isolated_manager):
    resp = client.get("/api/runtime-clusters/does-not-exist/install.sh")
    assert resp.status_code == 404


def test_get_simulation_script_embeds_the_real_event_generator_image(isolated_manager):
    create_resp = client.post("/api/runtime-clusters", json={"name": "prod-eks"})
    cluster_id = create_resp.json()["id"]

    resp = client.get(f"/api/runtime-clusters/{cluster_id}/simulate.sh")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/x-shellscript")
    assert "falcosecurity/event-generator" in resp.text
    assert "prod-eks" in resp.text


def test_get_simulation_script_404_for_unknown_cluster(isolated_manager):
    resp = client.get("/api/runtime-clusters/does-not-exist/simulate.sh")
    assert resp.status_code == 404


def test_ingest_event_stores_a_real_finding(isolated_manager):
    create_resp = client.post("/api/runtime-clusters", json={"name": "prod-eks"})
    cluster_id = create_resp.json()["id"]
    token = create_resp.json()["install_token"]

    resp = client.post(f"/api/runtime-clusters/{cluster_id}/events?token={token}", json=_REAL_ALERT_PAYLOAD)
    assert resp.status_code == 204

    detail = client.get(f"/api/runtime-clusters/{cluster_id}").json()
    assert detail["finding_count"] == 1
    assert detail["findings"][0]["rule_id"] == "Read sensitive file untrusted"
    assert detail["findings"][0]["severity"] == "medium"


def test_ingest_event_rejects_wrong_token(isolated_manager):
    create_resp = client.post("/api/runtime-clusters", json={"name": "prod-eks"})
    cluster_id = create_resp.json()["id"]

    resp = client.post(f"/api/runtime-clusters/{cluster_id}/events?token=wrong", json=_REAL_ALERT_PAYLOAD)
    assert resp.status_code == 401


def test_ingest_event_404_for_unknown_cluster(isolated_manager):
    resp = client.post("/api/runtime-clusters/does-not-exist/events?token=x", json=_REAL_ALERT_PAYLOAD)
    assert resp.status_code == 404


def test_ingest_event_rejects_malformed_alert_payload(isolated_manager):
    create_resp = client.post("/api/runtime-clusters", json={"name": "prod-eks"})
    cluster_id = create_resp.json()["id"]
    token = create_resp.json()["install_token"]

    resp = client.post(f"/api/runtime-clusters/{cluster_id}/events?token={token}", json={"not": "a falco alert"})
    assert resp.status_code == 400


def test_ingest_event_rejects_non_json_body(isolated_manager):
    create_resp = client.post("/api/runtime-clusters", json={"name": "prod-eks"})
    cluster_id = create_resp.json()["id"]
    token = create_resp.json()["install_token"]

    resp = client.post(
        f"/api/runtime-clusters/{cluster_id}/events?token={token}",
        content=b"not json",
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 400


def test_report_download_returns_real_content(isolated_manager):
    create_resp = client.post("/api/runtime-clusters", json={"name": "prod-eks"})
    cluster_id = create_resp.json()["id"]
    token = create_resp.json()["install_token"]
    client.post(f"/api/runtime-clusters/{cluster_id}/events?token={token}", json=_REAL_ALERT_PAYLOAD)

    resp = client.get(f"/api/runtime-clusters/{cluster_id}/report.sarif")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/sarif+json")
    assert resp.json()["runs"]


def test_report_download_works_before_any_findings(isolated_manager):
    create_resp = client.post("/api/runtime-clusters", json={"name": "prod-eks"})
    cluster_id = create_resp.json()["id"]

    resp = client.get(f"/api/runtime-clusters/{cluster_id}/report.json")
    assert resp.status_code == 200


def test_report_download_404_for_unknown_cluster(isolated_manager):
    resp = client.get("/api/runtime-clusters/does-not-exist/report.json")
    assert resp.status_code == 404


def test_report_download_unknown_format_404s(isolated_manager):
    create_resp = client.post("/api/runtime-clusters", json={"name": "prod-eks"})
    cluster_id = create_resp.json()["id"]
    resp = client.get(f"/api/runtime-clusters/{cluster_id}/report.yaml")
    assert resp.status_code == 404


def test_report_download_all_five_formats(isolated_manager):
    create_resp = client.post("/api/runtime-clusters", json={"name": "prod-eks"})
    cluster_id = create_resp.json()["id"]
    token = create_resp.json()["install_token"]
    client.post(f"/api/runtime-clusters/{cluster_id}/events?token={token}", json=_REAL_ALERT_PAYLOAD)

    for fmt in ("sarif", "json", "csv", "html", "pdf"):
        resp = client.get(f"/api/runtime-clusters/{cluster_id}/report.{fmt}")
        assert resp.status_code in (200, 503), f"{fmt} returned {resp.status_code}"
        if resp.status_code == 200:
            assert len(resp.content) > 0
