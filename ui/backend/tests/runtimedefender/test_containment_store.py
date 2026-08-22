import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.runtimedefender import containment_models  # noqa: F401 -- registers tables on Base.metadata
from app.runtimedefender.containment_store import (
    CommandNotFound,
    InvalidCommandTransition,
    UnknownCommandStatus,
    UnknownResponseAction,
    enqueue_command,
    get_response_action,
    list_actionable_commands,
    list_pending_commands,
    list_response_rules,
    request_release,
    update_command_status,
    upsert_response_rule,
)


@pytest.fixture
def session():
    # In-memory SQLite, isolated per test -- StaticPool keeps the same
    # connection (and thus the same in-memory DB) alive across the session
    # instead of SQLAlchemy's default pooling handing out a fresh :memory:
    # database per checkout.
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, future=True)
    db_session = factory()
    try:
        yield db_session
    finally:
        db_session.close()
        engine.dispose()


# ---- response rules -------------------------------------------------


def test_get_response_action_returns_none_for_unmapped_rule(session):
    assert get_response_action(session, "Some Unmapped Rule") is None


def test_upsert_then_get_response_action_round_trips(session):
    upsert_response_rule(session, "Contact K8S API Server From Container", "isolate_network")
    session.commit()
    assert get_response_action(session, "Contact K8S API Server From Container") == "isolate_network"


def test_upsert_response_rule_rejects_unknown_action(session):
    with pytest.raises(UnknownResponseAction):
        upsert_response_rule(session, "Some Rule", "reboot_the_datacenter")


def test_upsert_response_rule_updates_an_existing_mapping(session):
    upsert_response_rule(session, "rule-a", "log_only")
    session.commit()
    upsert_response_rule(session, "rule-a", "isolate_network")
    session.commit()

    rules = list_response_rules(session)
    assert len(rules) == 1
    assert rules[0].action == "isolate_network"


def test_get_response_action_returns_none_when_rule_disabled(session):
    upsert_response_rule(session, "rule-a", "isolate_network", enabled=False)
    session.commit()
    assert get_response_action(session, "rule-a") is None


def test_list_response_rules_is_sorted_by_rule_id(session):
    upsert_response_rule(session, "zzz-rule", "log_only")
    upsert_response_rule(session, "aaa-rule", "log_only")
    session.commit()

    rules = list_response_rules(session)
    assert [r.rule_id for r in rules] == ["aaa-rule", "zzz-rule"]


# ---- response commands -----------------------------------------------


def test_enqueue_command_creates_a_pending_command(session):
    command = enqueue_command(
        session, cluster_id="c1", namespace="default", pod_name="victim-abc", action="isolate_network"
    )
    session.commit()

    assert command.status == "pending"
    assert command.cluster_id == "c1"
    pending = list_pending_commands(session, "c1")
    assert len(pending) == 1
    assert pending[0].id == command.id


def test_enqueue_command_rejects_log_only_as_not_enqueueable(session):
    with pytest.raises(UnknownResponseAction):
        enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="log_only")


def test_enqueue_command_rejects_unknown_action(session):
    with pytest.raises(UnknownResponseAction):
        enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="not_a_real_action")


def test_enqueue_command_is_idempotent_for_the_same_pending_target(session):
    first = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="isolate_network")
    session.commit()
    second = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="isolate_network")
    session.commit()

    assert first.id == second.id
    assert len(list_pending_commands(session, "c1")) == 1


def test_enqueue_command_honors_an_explicit_idempotency_key(session):
    first = enqueue_command(
        session, cluster_id="c1", namespace="default", pod_name="pod-a", action="isolate_network",
        idempotency_key="finding-42",
    )
    session.commit()
    second = enqueue_command(
        session, cluster_id="c1", namespace="default", pod_name="pod-a", action="isolate_network",
        idempotency_key="finding-42",
    )
    session.commit()

    assert first.id == second.id


def test_list_pending_commands_is_scoped_to_one_cluster(session):
    enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="isolate_network")
    enqueue_command(session, cluster_id="c2", namespace="default", pod_name="pod-b", action="isolate_network")
    session.commit()

    assert [c.cluster_id for c in list_pending_commands(session, "c1")] == ["c1"]
    assert [c.cluster_id for c in list_pending_commands(session, "c2")] == ["c2"]


def test_list_pending_commands_excludes_non_pending(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="isolate_network")
    session.commit()
    update_command_status(session, command.id, "applied")
    session.commit()

    assert list_pending_commands(session, "c1") == []


def test_update_command_status_applies_a_valid_transition(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="isolate_network")
    session.commit()

    updated = update_command_status(session, command.id, "applied")
    session.commit()

    assert updated.status == "applied"


def test_update_command_status_rejects_unknown_status(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="isolate_network")
    session.commit()

    with pytest.raises(UnknownCommandStatus):
        update_command_status(session, command.id, "obliterated")


def test_update_command_status_raises_for_unknown_command_id(session):
    with pytest.raises(CommandNotFound):
        update_command_status(session, "does-not-exist", "applied")


# ---- release flow -----------------------------------------------------


def test_request_release_moves_an_applied_command_to_release_pending(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="isolate_network")
    session.commit()
    update_command_status(session, command.id, "applied")
    session.commit()

    released = request_release(session, command.id)
    session.commit()

    assert released.status == "release_pending"


def test_request_release_rejects_a_command_that_was_never_applied(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="isolate_network")
    session.commit()

    with pytest.raises(InvalidCommandTransition):
        request_release(session, command.id)


def test_request_release_rejects_a_kill_process_command_even_when_applied(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="kill_process")
    session.commit()
    update_command_status(session, command.id, "applied")
    session.commit()

    with pytest.raises(InvalidCommandTransition):
        request_release(session, command.id)


def test_request_release_rejects_a_quarantine_node_command_even_when_applied(session):
    command = enqueue_command(
        session, cluster_id="c1", namespace="default", pod_name="pod-a", action="quarantine_node"
    )
    session.commit()
    update_command_status(session, command.id, "applied")
    session.commit()

    with pytest.raises(InvalidCommandTransition):
        request_release(session, command.id)


def test_request_release_raises_for_unknown_command_id(session):
    with pytest.raises(CommandNotFound):
        request_release(session, "does-not-exist")


def test_list_actionable_commands_includes_pending_and_release_pending(session):
    to_apply = enqueue_command(
        session, cluster_id="c1", namespace="default", pod_name="pod-a", action="isolate_network"
    )
    to_release = enqueue_command(
        session, cluster_id="c1", namespace="default", pod_name="pod-b", action="isolate_network"
    )
    session.commit()
    update_command_status(session, to_release.id, "applied")
    session.commit()
    request_release(session, to_release.id)
    session.commit()

    actionable = list_actionable_commands(session, "c1")
    assert {c.id for c in actionable} == {to_apply.id, to_release.id}


def test_list_actionable_commands_excludes_terminal_states(session):
    applied = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="isolate_network")
    failed = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-b", action="isolate_network")
    session.commit()
    update_command_status(session, applied.id, "applied")
    update_command_status(session, failed.id, "failed")
    session.commit()

    assert list_actionable_commands(session, "c1") == []


def test_list_actionable_commands_is_scoped_to_one_cluster(session):
    enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="isolate_network")
    enqueue_command(session, cluster_id="c2", namespace="default", pod_name="pod-b", action="isolate_network")
    session.commit()

    assert [c.cluster_id for c in list_actionable_commands(session, "c1")] == ["c1"]


# ---- cross-cluster ownership scoping -----------------------------------


def test_update_command_status_rejects_a_command_belonging_to_another_cluster(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="isolate_network")
    session.commit()

    with pytest.raises(CommandNotFound):
        update_command_status(session, command.id, "applied", cluster_id="c2")


def test_update_command_status_succeeds_when_cluster_id_matches(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="isolate_network")
    session.commit()

    updated = update_command_status(session, command.id, "applied", cluster_id="c1")
    assert updated.status == "applied"


def test_request_release_rejects_a_command_belonging_to_another_cluster(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="isolate_network")
    session.commit()
    update_command_status(session, command.id, "applied")
    session.commit()

    with pytest.raises(CommandNotFound):
        request_release(session, command.id, cluster_id="c2")
