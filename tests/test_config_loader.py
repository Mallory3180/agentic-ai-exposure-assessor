"""Tests for YAML inventory loading."""

from __future__ import annotations

import pytest
from sqlmodel import select

from agentic_ai_exposure_assessor import config_loader, models


def test_load_directory_inserts_records(temp_db, fixtures_dir):
    with temp_db.session_scope() as session:
        counts = config_loader.load_directory(fixtures_dir, session)
    assert counts["Agent"] >= 5
    assert counts["Tool"] >= 6
    assert counts["Permission"] >= 1
    assert counts["DataSource"] >= 1
    assert counts["ApprovalPolicy"] >= 1


def test_agents_have_expected_fields(temp_db, fixtures_dir):
    with temp_db.session_scope() as session:
        config_loader.load_directory(fixtures_dir, session)
    with temp_db.session_scope() as session:
        agents = session.exec(select(models.Agent)).all()
        by_id = {a.agent_id: a for a in agents}
        assert "customer-support-agent" in by_id
        cs = by_id["customer-support-agent"]
        assert "send_email" in cs.allowed_tools
        assert cs.connected_data_sources == ["customer_db"]
        # legacy-batch-agent intentionally has no owner.
        assert by_id["legacy-batch-agent"].owner == ""


def test_invalid_yaml_raises_config_error(temp_db, tmp_path):
    bad = tmp_path / "agent_inventory.yml"
    bad.write_text("agents: [ this is : : not valid yaml", encoding="utf-8")
    with temp_db.session_scope() as session:
        with pytest.raises(config_loader.ConfigError):
            config_loader.load_directory(tmp_path, session)


def test_missing_directory_raises(temp_db, tmp_path):
    missing = tmp_path / "does_not_exist"
    with temp_db.session_scope() as session:
        with pytest.raises(config_loader.ConfigError):
            config_loader.load_directory(missing, session)
