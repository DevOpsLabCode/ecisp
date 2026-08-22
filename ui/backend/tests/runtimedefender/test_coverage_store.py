import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.runtimedefender import coverage_models  # noqa: F401 -- registers tables on Base.metadata
from app.runtimedefender.coverage_store import (
    InvalidAccountId,
    UnknownCoverageStatus,
    get_cluster_coverage,
    list_aws_account_coverage,
    list_cluster_coverage,
    record_responder_heartbeat,
    register_aws_account,
    report_aws_account_assume_role,
    report_falco_daemonset_health,
    report_kill_process_capability,
    report_network_policy_enforcement,
    report_quarantine_node_capability,
)


@pytest.fixture
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, future=True)
    db_session = factory()
    try:
        yield db_session
    finally:
        db_session.close()
        engine.dispose()


# ---- responder heartbeat -------------------------------------------------


def test_get_cluster_coverage_returns_none_before_any_signal(session):
    assert get_cluster_coverage(session, "c1") is None


def test_record_responder_heartbeat_creates_a_row_on_first_call(session):
    coverage = record_responder_heartbeat(session, "c1")
    session.commit()

    assert coverage.cluster_id == "c1"
    assert coverage.responder_last_seen_at is not None
    assert coverage.network_policy_enforcement == "unverified"  # default, untouched by a heartbeat


def test_record_responder_heartbeat_updates_an_existing_row(session):
    first = record_responder_heartbeat(session, "c1")
    session.commit()
    first_seen = first.responder_last_seen_at

    second = record_responder_heartbeat(session, "c1")
    session.commit()

    assert second.responder_last_seen_at >= first_seen
    assert list_cluster_coverage(session) == [second]  # one row, not two


# ---- network policy enforcement -------------------------------------------


def test_report_network_policy_enforcement_verified(session):
    coverage = report_network_policy_enforcement(session, "c1", "verified")
    session.commit()

    assert coverage.network_policy_enforcement == "verified"
    assert coverage.network_policy_checked_at is not None


def test_report_network_policy_enforcement_failed(session):
    coverage = report_network_policy_enforcement(session, "c1", "failed")
    session.commit()

    assert coverage.network_policy_enforcement == "failed"


def test_report_network_policy_enforcement_rejects_unknown_status(session):
    with pytest.raises(UnknownCoverageStatus):
        report_network_policy_enforcement(session, "c1", "sort-of-working")


def test_report_network_policy_enforcement_can_regress_from_verified_to_failed(session):
    # The exact scenario this whole system exists to catch -- a cluster
    # that was verified yesterday and comes back failed today (e.g. a CNI
    # config change).
    report_network_policy_enforcement(session, "c1", "verified")
    session.commit()

    regressed = report_network_policy_enforcement(session, "c1", "failed")
    session.commit()

    assert regressed.network_policy_enforcement == "failed"


def test_report_network_policy_enforcement_does_not_touch_the_heartbeat(session):
    record_responder_heartbeat(session, "c1")
    session.commit()

    coverage = report_network_policy_enforcement(session, "c1", "verified")
    session.commit()

    assert coverage.responder_last_seen_at is not None


# ---- fleet-wide listing ----------------------------------------------------


def test_list_cluster_coverage_is_sorted_by_cluster_id(session):
    record_responder_heartbeat(session, "zzz-cluster")
    record_responder_heartbeat(session, "aaa-cluster")
    session.commit()

    coverage = list_cluster_coverage(session)
    assert [c.cluster_id for c in coverage] == ["aaa-cluster", "zzz-cluster"]


def test_list_cluster_coverage_is_empty_by_default(session):
    assert list_cluster_coverage(session) == []


def test_heartbeat_and_network_policy_report_share_the_same_row(session):
    record_responder_heartbeat(session, "c1")
    session.commit()
    report_network_policy_enforcement(session, "c1", "verified")
    session.commit()

    coverage = get_cluster_coverage(session, "c1")
    assert coverage.responder_last_seen_at is not None
    assert coverage.network_policy_enforcement == "verified"
    assert len(list_cluster_coverage(session)) == 1


# ---- Falco DaemonSet health -------------------------------------------


def test_report_falco_daemonset_health_healthy(session):
    coverage = report_falco_daemonset_health(session, "c1", "healthy", ready=5, desired=5)
    session.commit()

    assert coverage.falco_daemonset_status == "healthy"
    assert coverage.falco_daemonset_ready == 5
    assert coverage.falco_daemonset_desired == 5
    assert coverage.falco_checked_at is not None


def test_report_falco_daemonset_health_degraded(session):
    coverage = report_falco_daemonset_health(session, "c1", "degraded", ready=3, desired=5)
    session.commit()

    assert coverage.falco_daemonset_status == "degraded"
    assert coverage.falco_daemonset_ready == 3


def test_report_falco_daemonset_health_unknown_without_counts(session):
    coverage = report_falco_daemonset_health(session, "c1", "unknown")
    session.commit()

    assert coverage.falco_daemonset_status == "unknown"
    assert coverage.falco_daemonset_ready is None
    assert coverage.falco_daemonset_desired is None


def test_report_falco_daemonset_health_rejects_unknown_status(session):
    with pytest.raises(UnknownCoverageStatus):
        report_falco_daemonset_health(session, "c1", "sort-of-healthy")


# ---- kill_process / quarantine_node capability -------------------------


def test_report_kill_process_capability_verified(session):
    coverage = report_kill_process_capability(session, "c1", "verified")
    session.commit()

    assert coverage.kill_process_capability == "verified"
    assert coverage.kill_process_checked_at is not None


def test_report_kill_process_capability_rejects_unknown_status(session):
    with pytest.raises(UnknownCoverageStatus):
        report_kill_process_capability(session, "c1", "maybe")


def test_report_quarantine_node_capability_failed(session):
    coverage = report_quarantine_node_capability(session, "c1", "failed")
    session.commit()

    assert coverage.quarantine_node_capability == "failed"


def test_report_quarantine_node_capability_rejects_unknown_status(session):
    with pytest.raises(UnknownCoverageStatus):
        report_quarantine_node_capability(session, "c1", "maybe")


def test_capability_reports_do_not_touch_unrelated_fields(session):
    report_kill_process_capability(session, "c1", "verified")
    session.commit()
    report_quarantine_node_capability(session, "c1", "failed")
    session.commit()

    coverage = get_cluster_coverage(session, "c1")
    assert coverage.kill_process_capability == "verified"
    assert coverage.quarantine_node_capability == "failed"
    assert coverage.network_policy_enforcement == "unverified"  # untouched


# ---- AWS account coverage (Tier 4) --------------------------------------


def test_register_aws_account_creates_a_row(session):
    account = register_aws_account(session, "123456789012")
    session.commit()

    assert account.account_id == "123456789012"
    assert account.assume_role_status == "unverified"


def test_register_aws_account_is_idempotent(session):
    register_aws_account(session, "123456789012")
    session.commit()
    register_aws_account(session, "123456789012")
    session.commit()

    assert len(list_aws_account_coverage(session)) == 1


def test_register_aws_account_rejects_a_non_12_digit_id(session):
    with pytest.raises(InvalidAccountId):
        register_aws_account(session, "not-an-account-id")


def test_register_aws_account_rejects_wrong_length(session):
    with pytest.raises(InvalidAccountId):
        register_aws_account(session, "12345")


def test_report_aws_account_assume_role_verified(session):
    register_aws_account(session, "123456789012")
    session.commit()

    account = report_aws_account_assume_role(session, "123456789012", "verified")
    session.commit()

    assert account.assume_role_status == "verified"
    assert account.checked_at is not None


def test_report_aws_account_assume_role_raises_for_unregistered_account(session):
    with pytest.raises(InvalidAccountId):
        report_aws_account_assume_role(session, "123456789012", "verified")


def test_report_aws_account_assume_role_rejects_unknown_status(session):
    register_aws_account(session, "123456789012")
    session.commit()

    with pytest.raises(UnknownCoverageStatus):
        report_aws_account_assume_role(session, "123456789012", "sort-of-works")


def test_list_aws_account_coverage_is_sorted(session):
    register_aws_account(session, "222222222222")
    register_aws_account(session, "111111111111")
    session.commit()

    accounts = list_aws_account_coverage(session)
    assert [a.account_id for a in accounts] == ["111111111111", "222222222222"]
