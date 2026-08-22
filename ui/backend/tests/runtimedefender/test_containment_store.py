import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.runtimedefender import containment_models  # noqa: F401 -- registers tables on Base.metadata
from app.runtimedefender.containment_store import (
    MAX_APPLY_ATTEMPTS,
    CommandNotFound,
    InvalidCommandTransition,
    UnknownCommandStatus,
    UnknownResponseAction,
    enqueue_command,
    get_response_action,
    list_actionable_commands,
    list_commands_for_iam_component,
    list_pending_commands,
    list_response_rules,
    request_release,
    resolve_iam_role,
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


def test_update_command_status_immediate_terminal_failure_for_non_retryable_action(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="isolate_network")
    session.commit()

    updated = update_command_status(session, command.id, "failed")
    session.commit()

    assert updated.status == "failed"
    assert updated.attempts == 0  # non-retryable actions don't use the counter at all


def test_update_command_status_failed_for_retryable_action_stays_pending_and_counts_attempts(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="quarantine_node")
    session.commit()

    updated = update_command_status(session, command.id, "failed")
    session.commit()

    assert updated.status == "pending"  # unchanged -- next poll retries
    assert updated.attempts == 1


def test_update_command_status_goes_terminal_after_max_apply_attempts(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="quarantine_node")
    session.commit()

    for _ in range(MAX_APPLY_ATTEMPTS - 1):
        update_command_status(session, command.id, "failed")
        session.commit()
        assert command.status == "pending"

    updated = update_command_status(session, command.id, "failed")
    session.commit()

    assert updated.attempts == MAX_APPLY_ATTEMPTS
    assert updated.status == "failed"


def test_update_command_status_applied_for_retryable_action_still_goes_terminal(session):
    # A success report is a plain terminal transition regardless of action
    # -- the retry counter only intercepts "failed" reports.
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="quarantine_node")
    session.commit()

    updated = update_command_status(session, command.id, "applied")
    session.commit()

    assert updated.status == "applied"


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


# ---- revoke_iam (Tier 4) role resolution ---------------------------------


def test_resolve_iam_role_moves_a_pending_command_to_role_resolved(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="revoke_iam")
    session.commit()

    resolved = resolve_iam_role(session, command.id, "arn:aws:iam::111111111111:role/my-workload-role")
    session.commit()

    assert resolved.status == "role_resolved"
    assert resolved.resolved_role_arn == "arn:aws:iam::111111111111:role/my-workload-role"


def test_resolve_iam_role_rejects_a_non_revoke_iam_command(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="isolate_network")
    session.commit()

    with pytest.raises(InvalidCommandTransition):
        resolve_iam_role(session, command.id, "arn:aws:iam::111111111111:role/my-workload-role")


def test_resolve_iam_role_rejects_a_command_not_in_pending(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="revoke_iam")
    session.commit()
    resolve_iam_role(session, command.id, "arn:aws:iam::111111111111:role/my-workload-role")
    session.commit()

    with pytest.raises(InvalidCommandTransition):
        resolve_iam_role(session, command.id, "arn:aws:iam::111111111111:role/my-workload-role")


def test_resolve_iam_role_rejects_a_command_belonging_to_another_cluster(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="revoke_iam")
    session.commit()

    with pytest.raises(CommandNotFound):
        resolve_iam_role(session, command.id, "arn:aws:iam::111111111111:role/x", cluster_id="c2")


def test_enqueue_command_dedupes_against_role_resolved_state(session):
    first = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="revoke_iam")
    session.commit()
    resolve_iam_role(session, first.id, "arn:aws:iam::111111111111:role/x")
    session.commit()

    second = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="revoke_iam")
    session.commit()

    assert first.id == second.id


# ---- Tier 4 privilege separation ------------------------------------------


def test_list_actionable_commands_never_returns_a_pending_revoke_iam_apply_action(session):
    # The in-cluster responder DOES see a pending revoke_iam command (it
    # needs to resolve the role ARN), but it must never be handed anything
    # that looks like "go ahead and apply this" for revoke_iam -- that's
    # only ever the IAM component's job. This test documents that the
    # command IS visible (for resolution), while the two tests below
    # confirm the states the in-cluster responder truly must never see.
    enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="revoke_iam")
    session.commit()

    actionable = list_actionable_commands(session, "c1")
    assert len(actionable) == 1
    assert actionable[0].status == "pending"


def test_list_actionable_commands_excludes_role_resolved(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="revoke_iam")
    session.commit()
    resolve_iam_role(session, command.id, "arn:aws:iam::111111111111:role/x")
    session.commit()

    assert list_actionable_commands(session, "c1") == []


def test_list_actionable_commands_excludes_revoke_iam_release_pending(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="revoke_iam")
    session.commit()
    resolve_iam_role(session, command.id, "arn:aws:iam::111111111111:role/x")
    update_command_status(session, command.id, "applied")
    session.commit()
    request_release(session, command.id)
    session.commit()

    assert command.status == "release_pending"
    assert list_actionable_commands(session, "c1") == []


def test_list_commands_for_iam_component_is_fleet_wide(session):
    c1_command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="revoke_iam")
    c2_command = enqueue_command(session, cluster_id="c2", namespace="default", pod_name="pod-b", action="revoke_iam")
    session.commit()
    resolve_iam_role(session, c1_command.id, "arn:aws:iam::111111111111:role/a")
    resolve_iam_role(session, c2_command.id, "arn:aws:iam::222222222222:role/b")
    session.commit()

    fleet_wide = list_commands_for_iam_component(session)
    assert {c.id for c in fleet_wide} == {c1_command.id, c2_command.id}


def test_list_commands_for_iam_component_includes_role_resolved_and_release_pending(session):
    to_apply = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="revoke_iam")
    to_release = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-b", action="revoke_iam")
    session.commit()
    resolve_iam_role(session, to_apply.id, "arn:aws:iam::111111111111:role/a")
    resolve_iam_role(session, to_release.id, "arn:aws:iam::111111111111:role/b")
    update_command_status(session, to_release.id, "applied")
    session.commit()
    request_release(session, to_release.id)
    session.commit()

    fleet_wide = list_commands_for_iam_component(session)
    assert {c.id for c in fleet_wide} == {to_apply.id, to_release.id}


def test_list_commands_for_iam_component_excludes_other_actions_release_pending(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="isolate_network")
    session.commit()
    update_command_status(session, command.id, "applied")
    session.commit()
    request_release(session, command.id)
    session.commit()

    # isolate_network's release_pending belongs to the in-cluster
    # responder, never to the IAM component.
    assert list_commands_for_iam_component(session) == []


def test_request_release_works_for_an_applied_revoke_iam_command(session):
    command = enqueue_command(session, cluster_id="c1", namespace="default", pod_name="pod-a", action="revoke_iam")
    session.commit()
    resolve_iam_role(session, command.id, "arn:aws:iam::111111111111:role/x")
    update_command_status(session, command.id, "applied")
    session.commit()

    released = request_release(session, command.id)
    session.commit()

    assert released.status == "release_pending"
