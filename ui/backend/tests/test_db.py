from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import db
from app.runtimedefender.containment_models import ResponseRule


@pytest.fixture
def memory_factory():
    # Mirrors how a real deployment's engine is built (see db.py), just
    # pointed at an isolated in-memory SQLite DB instead of DATABASE_URL,
    # so this test never touches the module-level `db.engine`/`db.SessionLocal`.
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    db.init_db(bind=engine)
    return sessionmaker(bind=engine, future=True)


def test_init_db_creates_the_containment_tables(memory_factory):
    session = memory_factory()
    try:
        assert session.query(ResponseRule).count() == 0
    finally:
        session.close()


def test_session_scope_commits_on_a_clean_exit(memory_factory):
    with db.session_scope(memory_factory) as session:
        session.add(
            ResponseRule(
                rule_id="r1", action="isolate_network", enabled=True,
                created_at=datetime.now(UTC), updated_at=datetime.now(UTC),
            )
        )

    verify = memory_factory()
    try:
        assert verify.query(ResponseRule).count() == 1
    finally:
        verify.close()


def test_session_scope_rolls_back_on_exception(memory_factory):
    with pytest.raises(RuntimeError):
        with db.session_scope(memory_factory) as session:
            session.add(
                ResponseRule(
                    rule_id="r1", action="isolate_network", enabled=True,
                    created_at=datetime.now(UTC), updated_at=datetime.now(UTC),
                )
            )
            raise RuntimeError("boom")

    verify = memory_factory()
    try:
        assert verify.query(ResponseRule).count() == 0
    finally:
        verify.close()


def test_session_scope_defaults_to_the_module_level_session_local():
    # Doesn't assert on real DB effects (that would touch the module-level
    # sqlite file) -- just confirms the no-argument path opens and cleanly
    # tears down a real SessionLocal-backed session.
    with db.session_scope() as session:
        assert session.bind is db.engine
