import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.runtimedefender import coverage_models  # noqa: F401 -- registers tables on Base.metadata
from app.runtimedefender.coverage_store import (
    UnknownCoverageStatus,
    get_cluster_coverage,
    list_cluster_coverage,
    record_responder_heartbeat,
    report_network_policy_enforcement,
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
