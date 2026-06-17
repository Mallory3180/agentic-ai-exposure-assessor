"""Database engine & session management.

Uses SQLite via a relative path (``./data/app.db`` by default). The directory is created
from Python so there is no dependency on ``mkdir -p`` or any OS specific command. The DB
path can be overridden with the ``AAEA_DB_PATH`` environment variable, which is handy for
tests (each test can point at a temporary file).
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, create_engine

# Importing models registers them on SQLModel.metadata so create_all works.
from . import models  # noqa: F401

DEFAULT_DB_PATH = Path("data") / "app.db"

_engine: Engine | None = None


def get_db_path() -> Path:
    """Return the configured SQLite path (env override aware)."""
    raw = os.environ.get("AAEA_DB_PATH")
    return Path(raw) if raw else DEFAULT_DB_PATH


def get_engine() -> Engine:
    """Return a cached SQLAlchemy engine, creating parent dirs as needed."""
    global _engine
    if _engine is None:
        db_path = get_db_path()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        # as_posix keeps the URL valid on Windows (backslashes break sqlite URLs).
        url = f"sqlite:///{db_path.as_posix()}"
        _engine = create_engine(url, echo=False, connect_args={"check_same_thread": False})
    return _engine


def reset_engine() -> None:
    """Drop the cached engine (used by tests that switch DB paths)."""
    global _engine
    if _engine is not None:
        _engine.dispose()
    _engine = None


def init_db() -> None:
    """Create all tables if they do not exist."""
    SQLModel.metadata.create_all(get_engine())


def reset_db() -> None:
    """Drop and recreate all tables."""
    engine = get_engine()
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Context-managed session that commits on success and rolls back on error.

    ``expire_on_commit=False`` keeps attribute values populated on returned objects after
    the session closes, so callers (CLI, report builders, tests) can read them safely.
    """
    session = Session(get_engine(), expire_on_commit=False)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session() -> Iterator[Session]:
    """FastAPI dependency that yields a session."""
    with Session(get_engine(), expire_on_commit=False) as session:
        yield session
