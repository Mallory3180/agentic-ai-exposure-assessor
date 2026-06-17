"""Shared pytest fixtures: an isolated SQLite database per test."""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = REPO_ROOT / "fixtures"


@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    """Point the app at a temporary SQLite file and reset the engine."""
    from agentic_ai_exposure_assessor import db

    db_path = tmp_path / "test_app.db"
    monkeypatch.setenv("AAEA_DB_PATH", str(db_path))
    db.reset_engine()
    db.init_db()
    yield db
    db.reset_engine()


@pytest.fixture()
def fixtures_dir() -> Path:
    return FIXTURES_DIR
