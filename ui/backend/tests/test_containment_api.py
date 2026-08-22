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


@pytest.fixture
def isolated_db(monkeypatch):
    # Mirrors `isolated_manager` above, for the containment tables --
    # without this, every test would share the same on-disk SQLite DB
    # (app/db.py's default), so a response rule mapped in one test would
    # still be mapped in the next.
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    db_module.init_db(bind=engine)
    monkeypatch.setattr(db_module, "SessionLocal", sessionmaker(bind=engine, future=True))
    monkeypatch.setattr(db_module, "engine", engine)
    return engine


def _create_cluster(name: str = "prod-eks") -> tuple[str, str]:
    resp = client.post("/api/runtime-clusters", json={"name": name})
    body = resp.json()
    return body["id"], body["install_token"]


# ---- responder install script ------------------------------------------


def test_get_responder_install_script_embeds_cluster_and_token(isolated_manager):
    cluster_id, token = _create_cluster()

    resp = client.get(f"/api/runtime-clusters/{cluster_id}/responder-install.sh")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/x-shellscript")
    assert f'value: "{cluster_id}"' in resp.text
    assert f'token: "{token}"' in resp.text
    assert "kubectl apply -f -" in resp.text


def test_get_responder_install_script_404_for_unknown_cluster(isolated_manager):
    resp = client.get("/api/runtime-clusters/does-not-exist/responder-install.sh")
    assert resp.status_code == 404


# ---- response rules ------------------------------------------------------


def test_upsert_response_rule_then_list_it(isolated_manager, isolated_db):
    resp = client.post(
        "/api/response-rules", json={"rule_id": "Read sensitive file untrusted", "action": "isolate_network"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["rule_id"] == "Read sensitive file untrusted"
    assert body["action"] == "isolate_network"
    assert body["enabled"] is True

    listed = client.get("/api/response-rules").json()
    assert len(listed) == 1
    assert listed[0]["rule_id"] == "Read sensitive file untrusted"


def test_upsert_response_rule_rejects_unknown_action(isolated_manager, isolated_db):
    resp = client.post("/api/response-rules", json={"rule_id": "some-rule", "action": "reboot_the_datacenter"})
    assert resp.status_code == 400


def test_list_response_rules_is_empty_by_default(isolated_manager, isolated_db):
    resp = client.get("/api/response-rules")
    assert resp.status_code == 200
    assert resp.json() == []


# ---- ingest -> enqueue wiring --------------------------------------------


def test_ingest_enqueues_a_command_when_the_rule_is_mapped(isolated_manager, isolated_db):
    client.post(
        "/api/response-rules", json={"rule_id": "Read sensitive file untrusted", "action": "isolate_network"}
    )
    cluster_id, token = _create_cluster()

    resp = client.post(f"/api/runtime-clusters/{cluster_id}/events?token={token}", json=_REAL_ALERT_PAYLOAD)
    assert resp.status_code == 204

    commands = client.get(f"/api/runtime-clusters/{cluster_id}/commands?token={token}").json()
    assert len(commands) == 1
    assert commands[0]["action"] == "isolate_network"
    assert commands[0]["status"] == "pending"
    assert commands[0]["pod_name"] == "test-victim"
    assert commands[0]["namespace"] == "default"


def test_ingest_does_not_enqueue_when_the_rule_is_unmapped(isolated_manager, isolated_db):
    cluster_id, token = _create_cluster()

    resp = client.post(f"/api/runtime-clusters/{cluster_id}/events?token={token}", json=_REAL_ALERT_PAYLOAD)
    assert resp.status_code == 204

    commands = client.get(f"/api/runtime-clusters/{cluster_id}/commands?token={token}").json()
    assert commands == []


def test_ingest_does_not_enqueue_when_the_alert_has_no_pod_or_namespace(isolated_manager, isolated_db):
    # A host-level Falco alert (no k8s.pod.name/k8s.ns.name in
    # output_fields) can still be a valid, mapped finding -- there's just
    # nothing for isolate_network to target.
    client.post(
        "/api/response-rules", json={"rule_id": "Read sensitive file untrusted", "action": "isolate_network"}
    )
    cluster_id, token = _create_cluster()
    host_level_payload = {
        "rule": "Read sensitive file untrusted",
        "priority": "Warning",
        "output": "16:23:00... command=cat /etc/shadow ...",
        "output_fields": {},
        "tags": ["T1555"],
    }

    resp = client.post(f"/api/runtime-clusters/{cluster_id}/events?token={token}", json=host_level_payload)
    assert resp.status_code == 204

    commands = client.get(f"/api/runtime-clusters/{cluster_id}/commands?token={token}").json()
    assert commands == []


def test_ingest_does_not_enqueue_for_a_log_only_mapping(isolated_manager, isolated_db):
    client.post("/api/response-rules", json={"rule_id": "Read sensitive file untrusted", "action": "log_only"})
    cluster_id, token = _create_cluster()

    client.post(f"/api/runtime-clusters/{cluster_id}/events?token={token}", json=_REAL_ALERT_PAYLOAD)

    commands = client.get(f"/api/runtime-clusters/{cluster_id}/commands?token={token}").json()
    assert commands == []


# ---- commands: poll endpoint ----------------------------------------------


def test_list_commands_rejects_wrong_token(isolated_manager, isolated_db):
    cluster_id, _token = _create_cluster()
    resp = client.get(f"/api/runtime-clusters/{cluster_id}/commands?token=wrong")
    assert resp.status_code == 401


def test_list_commands_404_for_unknown_cluster(isolated_manager, isolated_db):
    resp = client.get("/api/runtime-clusters/does-not-exist/commands?token=x")
    assert resp.status_code == 404


def test_list_commands_does_not_leak_another_clusters_commands(isolated_manager, isolated_db):
    client.post(
        "/api/response-rules", json={"rule_id": "Read sensitive file untrusted", "action": "isolate_network"}
    )
    cluster_a, token_a = _create_cluster("cluster-a")
    cluster_b, token_b = _create_cluster("cluster-b")
    client.post(f"/api/runtime-clusters/{cluster_a}/events?token={token_a}", json=_REAL_ALERT_PAYLOAD)

    commands_a = client.get(f"/api/runtime-clusters/{cluster_a}/commands?token={token_a}").json()
    commands_b = client.get(f"/api/runtime-clusters/{cluster_b}/commands?token={token_b}").json()
    assert len(commands_a) == 1
    assert commands_b == []


# ---- commands: status + release --------------------------------------------


def _update_status(cluster_id: str, token: str, command_id: str, status: str):
    return client.post(
        f"/api/runtime-clusters/{cluster_id}/commands/{command_id}/status?token={token}", json={"status": status}
    )


def _enqueue_one_command(isolated_manager) -> tuple[str, str, str]:
    client.post(
        "/api/response-rules", json={"rule_id": "Read sensitive file untrusted", "action": "isolate_network"}
    )
    cluster_id, token = _create_cluster()
    client.post(f"/api/runtime-clusters/{cluster_id}/events?token={token}", json=_REAL_ALERT_PAYLOAD)
    command_id = client.get(f"/api/runtime-clusters/{cluster_id}/commands?token={token}").json()[0]["id"]
    return cluster_id, token, command_id


def test_update_command_status_to_applied(isolated_manager, isolated_db):
    cluster_id, token, command_id = _enqueue_one_command(isolated_manager)

    resp = client.post(
        f"/api/runtime-clusters/{cluster_id}/commands/{command_id}/status?token={token}", json={"status": "applied"}
    )
    assert resp.status_code == 204

    commands = client.get(f"/api/runtime-clusters/{cluster_id}/commands?token={token}").json()
    assert commands == []  # "applied" is no longer actionable


def test_update_command_status_rejects_unknown_status(isolated_manager, isolated_db):
    cluster_id, token, command_id = _enqueue_one_command(isolated_manager)

    resp = client.post(
        f"/api/runtime-clusters/{cluster_id}/commands/{command_id}/status?token={token}",
        json={"status": "obliterated"},
    )
    assert resp.status_code == 400


def test_update_command_status_404_for_unknown_command(isolated_manager, isolated_db):
    cluster_id, token = _create_cluster()
    resp = client.post(
        f"/api/runtime-clusters/{cluster_id}/commands/does-not-exist/status?token={token}",
        json={"status": "applied"},
    )
    assert resp.status_code == 404


def test_update_command_status_rejects_wrong_cluster_token(isolated_manager, isolated_db):
    cluster_id, _token, command_id = _enqueue_one_command(isolated_manager)
    other_cluster_id, other_token = _create_cluster("other-cluster")

    resp = client.post(
        f"/api/runtime-clusters/{other_cluster_id}/commands/{command_id}/status?token={other_token}",
        json={"status": "applied"},
    )
    assert resp.status_code == 404


def test_release_after_applied_moves_to_release_pending(isolated_manager, isolated_db):
    cluster_id, token, command_id = _enqueue_one_command(isolated_manager)
    _update_status(cluster_id, token, command_id, "applied")

    resp = client.post(f"/api/runtime-clusters/{cluster_id}/commands/{command_id}/release")
    assert resp.status_code == 204

    commands = client.get(f"/api/runtime-clusters/{cluster_id}/commands?token={token}").json()
    assert len(commands) == 1
    assert commands[0]["status"] == "release_pending"


def test_release_rejects_a_command_that_was_never_applied(isolated_manager, isolated_db):
    cluster_id, _token, command_id = _enqueue_one_command(isolated_manager)

    resp = client.post(f"/api/runtime-clusters/{cluster_id}/commands/{command_id}/release")
    assert resp.status_code == 409


# ---- kill_process (Tier 2) -------------------------------------------------


def test_ingest_enqueues_a_kill_process_command_when_mapped(isolated_manager, isolated_db):
    client.post("/api/response-rules", json={"rule_id": "Read sensitive file untrusted", "action": "kill_process"})
    cluster_id, token = _create_cluster()

    resp = client.post(f"/api/runtime-clusters/{cluster_id}/events?token={token}", json=_REAL_ALERT_PAYLOAD)
    assert resp.status_code == 204

    commands = client.get(f"/api/runtime-clusters/{cluster_id}/commands?token={token}").json()
    assert len(commands) == 1
    assert commands[0]["action"] == "kill_process"
    assert commands[0]["status"] == "pending"


def test_release_rejects_an_applied_kill_process_command(isolated_manager, isolated_db):
    client.post("/api/response-rules", json={"rule_id": "Read sensitive file untrusted", "action": "kill_process"})
    cluster_id, token = _create_cluster()
    client.post(f"/api/runtime-clusters/{cluster_id}/events?token={token}", json=_REAL_ALERT_PAYLOAD)
    command_id = client.get(f"/api/runtime-clusters/{cluster_id}/commands?token={token}").json()[0]["id"]
    _update_status(cluster_id, token, command_id, "applied")

    resp = client.post(f"/api/runtime-clusters/{cluster_id}/commands/{command_id}/release")
    assert resp.status_code == 409


def test_release_404_for_unknown_command(isolated_manager, isolated_db):
    cluster_id, _token = _create_cluster()
    resp = client.post(f"/api/runtime-clusters/{cluster_id}/commands/does-not-exist/release")
    assert resp.status_code == 404


def test_full_lifecycle_pending_to_applied_to_release_pending_to_released(isolated_manager, isolated_db):
    cluster_id, token, command_id = _enqueue_one_command(isolated_manager)

    _update_status(cluster_id, token, command_id, "applied")
    client.post(f"/api/runtime-clusters/{cluster_id}/commands/{command_id}/release")
    resp = _update_status(cluster_id, token, command_id, "released")
    assert resp.status_code == 204

    commands = client.get(f"/api/runtime-clusters/{cluster_id}/commands?token={token}").json()
    assert commands == []  # "released" is terminal, no longer actionable
