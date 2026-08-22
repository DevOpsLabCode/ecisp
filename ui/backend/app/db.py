"""SQLAlchemy engine/session setup for durable Runtime Defender containment
state -- see `runtimedefender/containment_models.py`.

Everything else in this backend (org scans, code scans, registry scans,
Runtime Defender's own cluster/finding registry) is intentionally
job-scoped, in-memory, or report-file-based -- see
`runtimedefender/runtime_defender.py`'s own docstring for why that's the
right call there. This module exists specifically for the state that Phase 1
containment introduces and that a backend restart must *not* lose: the rule
-> response mapping (an operator's explicit opt-in decisions) and the
command queue an in-cluster responder polls. See the containment build plan,
Phase 0.

`DATABASE_URL` defaults to a local SQLite file so a bare `uvicorn
app.main:app` (or the test suite) needs no external service. Production
deployments set `DATABASE_URL` to a real Postgres DSN -- see
`ui/docker-compose.yml` and `alembic/env.py`.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from os import environ

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DATABASE_URL = environ.get("DATABASE_URL", "sqlite:///./data/golem_defender.db")

# SQLite's default driver refuses to share a connection across threads;
# FastAPI's threadpool-backed sync routes need that. Postgres (or any other
# real DSN) doesn't take this kwarg at all.
_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=_connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass


@contextmanager
def session_scope(factory: sessionmaker | None = None) -> Iterator[Session]:
    """Opens a session, commits on a clean exit, rolls back and re-raises
    otherwise. `factory` defaults to the module-level `SessionLocal` (real
    app code); tests pass their own factory bound to an isolated engine so
    this stays testable without touching global state."""
    session = (factory or SessionLocal)()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db(bind: Engine | None = None) -> None:
    """Creates tables directly from the ORM metadata. Used by local dev
    (app startup, see `main.py`) and by the test suite against a throwaway
    SQLite engine -- neither needs Alembic run first. A real deployment
    instead applies schema via `alembic upgrade head` (see `alembic/`),
    which is the only path that can also carry a schema forward across
    releases; this function only ever creates the current shape from
    scratch."""
    from .runtimedefender import containment_models  # noqa: F401 -- registers tables on Base.metadata

    Base.metadata.create_all(bind=bind or engine)
