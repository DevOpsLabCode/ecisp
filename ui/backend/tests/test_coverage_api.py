import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.db as db_module
from app import main
from app.main import app
from app.runtimedefender.runtime_defender import RuntimeDefenderManager

client = TestClient(app)


@pytest.fixture
def isolated_manager(monkeypatch):
    fresh = RuntimeDefenderManager()
    monkeypatch.setattr(main, "runtime_defender_manager", fresh)
    return fresh


@pytest.fixture
def isolated_db(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    db_module.init_db(bind=engine)
    monkeypatch.setattr(db_module, "SessionLocal", sessionmaker(bind=engine, future=True))
    monkeypatch.setattr(db_module, "engine", engine)
    return engine


def _create_cluster(name: str = "prod-eks") -> tuple[str, str]:
    resp = client.post("/api/runtime-clusters", json={"name": name})
    body = resp.json()
    return body["id"], body["install_token"]


# ---- responder heartbeat, via the existing poll route ----------------------


def test_polling_commands_records_a_heartbeat(isolated_manager, isolated_db):
    cluster_id, token = _create_cluster()

    resp = client.get(f"/api/runtime-clusters/{cluster_id}/commands?token={token}")
    assert resp.status_code == 200

    coverage = client.get(f"/api/runtime-clusters/{cluster_id}/coverage").json()
    assert coverage["responder_last_seen_at"] is not None
    assert coverage["network_policy_enforcement"] == "unverified"  # untouched by a heartbeat alone


def test_get_coverage_404_before_any_signal(isolated_manager, isolated_db):
    cluster_id, _token = _create_cluster()
    resp = client.get(f"/api/runtime-clusters/{cluster_id}/coverage")
    assert resp.status_code == 404


# ---- network policy coverage reporting -------------------------------------


def test_report_network_policy_coverage_verified(isolated_manager, isolated_db):
    cluster_id, token = _create_cluster()

    resp = client.post(
        f"/api/runtime-clusters/{cluster_id}/coverage/network-policy?token={token}", json={"status": "verified"}
    )
    assert resp.status_code == 204

    coverage = client.get(f"/api/runtime-clusters/{cluster_id}/coverage").json()
    assert coverage["network_policy_enforcement"] == "verified"
    assert coverage["network_policy_checked_at"] is not None


def test_report_network_policy_coverage_rejects_wrong_cluster_token(isolated_manager, isolated_db):
    cluster_id, _token = _create_cluster()
    _other_id, other_token = _create_cluster("other-cluster")

    resp = client.post(
        f"/api/runtime-clusters/{cluster_id}/coverage/network-policy?token={other_token}",
        json={"status": "verified"},
    )
    assert resp.status_code == 401


def test_report_network_policy_coverage_rejects_unknown_status(isolated_manager, isolated_db):
    cluster_id, token = _create_cluster()

    resp = client.post(
        f"/api/runtime-clusters/{cluster_id}/coverage/network-policy?token={token}",
        json={"status": "sort-of-working"},
    )
    assert resp.status_code == 400


def test_report_network_policy_coverage_404_for_unknown_cluster(isolated_manager, isolated_db):
    resp = client.post(
        "/api/runtime-clusters/does-not-exist/coverage/network-policy?token=x", json={"status": "verified"}
    )
    assert resp.status_code == 404


# ---- fleet-wide matrix ------------------------------------------------------


def test_list_coverage_is_fleet_wide(isolated_manager, isolated_db):
    cluster_a, token_a = _create_cluster("cluster-a")
    cluster_b, token_b = _create_cluster("cluster-b")
    client.get(f"/api/runtime-clusters/{cluster_a}/commands?token={token_a}")
    client.post(
        f"/api/runtime-clusters/{cluster_b}/coverage/network-policy?token={token_b}", json={"status": "failed"}
    )

    matrix = client.get("/api/coverage").json()
    ids = {c["cluster_id"] for c in matrix}
    assert ids == {cluster_a, cluster_b}

    by_id = {c["cluster_id"]: c for c in matrix}
    assert by_id[cluster_a]["responder_last_seen_at"] is not None
    assert by_id[cluster_b]["network_policy_enforcement"] == "failed"


def test_list_coverage_is_empty_by_default(isolated_manager, isolated_db):
    resp = client.get("/api/coverage")
    assert resp.status_code == 200
    assert resp.json() == []


def test_coverage_can_regress_from_verified_to_failed(isolated_manager, isolated_db):
    cluster_id, token = _create_cluster()
    client.post(
        f"/api/runtime-clusters/{cluster_id}/coverage/network-policy?token={token}", json={"status": "verified"}
    )

    resp = client.post(
        f"/api/runtime-clusters/{cluster_id}/coverage/network-policy?token={token}", json={"status": "failed"}
    )
    assert resp.status_code == 204

    coverage = client.get(f"/api/runtime-clusters/{cluster_id}/coverage").json()
    assert coverage["network_policy_enforcement"] == "failed"
