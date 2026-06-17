"""Tests for live inventory pull and the OTLP/HTTP trace receiver."""

from __future__ import annotations

import json
from pathlib import Path

from sqlmodel import select
from starlette.testclient import TestClient

from agentic_ai_exposure_assessor import models
from agentic_ai_exposure_assessor import targets as targets_mod
from agentic_ai_exposure_assessor.connectors import live
from agentic_ai_exposure_assessor.schemas import TargetIn

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = REPO_ROOT / "fixtures"


def test_generic_http_connector_returns_known_record_types(monkeypatch):
    target = TargetIn.model_validate(
        {"id": "t1", "platform": "generic_http", "inventory": {"base_url": "https://x/inv"}}
    )
    connector = live.GenericHttpInventoryConnector(target)

    payload = {
        "agents": [{"id": "a1", "name": "Agent 1", "owner": "o@e.com"}],
        "tools": [{"id": "t1", "name": "Tool 1", "risk_level": "high"}],
        "ignored": [{"foo": "bar"}],  # unknown key must be dropped
    }
    monkeypatch.setattr(connector, "_fetch", lambda url, headers: payload)
    records = connector.load()
    assert set(records) == {"agents", "tools"}
    assert records["agents"][0]["id"] == "a1"


def test_generic_http_connector_reads_token_from_env(monkeypatch):
    target = TargetIn.model_validate(
        {
            "id": "t1",
            "platform": "generic_http",
            "inventory": {"base_url": "https://x/inv", "token_env": "MY_TOKEN"},
        }
    )
    connector = live.GenericHttpInventoryConnector(target)
    captured: dict[str, dict] = {}

    def fake_fetch(url, headers):
        captured["headers"] = headers
        return {"agents": []}

    monkeypatch.setenv("MY_TOKEN", "secret-token-value")
    monkeypatch.setattr(connector, "_fetch", fake_fetch)
    connector.load()
    assert captured["headers"]["Authorization"] == "Bearer secret-token-value"


def test_cloud_connectors_are_documented_stubs():
    for platform in ("dify", "azure_openai", "bedrock", "mcp"):
        target = TargetIn.model_validate({"id": "t", "platform": platform})
        connector = live.build_inventory_connector(target)
        try:
            connector.load()
        except live.ConnectorNotConfigured as exc:
            assert connector.required_config  # documents what it needs
            assert "not implemented" in str(exc).lower()
        else:
            raise AssertionError(f"{platform} should raise ConnectorNotConfigured")


def test_pull_inventory_persists_records(temp_db):
    target = TargetIn.model_validate(
        {"id": "t1", "platform": "generic_http", "inventory": {"base_url": "https://x/inv"}}
    )

    def fake_load(self):
        return {
            "agents": [{"id": "live-agent", "name": "Live", "owner": "o@e.com"}],
            "tools": [{"id": "live-tool", "risk_level": "high"}],
        }

    import agentic_ai_exposure_assessor.connectors.live as live_mod

    orig = live_mod.GenericHttpInventoryConnector.load
    live_mod.GenericHttpInventoryConnector.load = fake_load  # type: ignore[assignment]
    try:
        with temp_db.session_scope() as session:
            result = targets_mod.pull_inventory([target], session)
    finally:
        live_mod.GenericHttpInventoryConnector.load = orig  # type: ignore[assignment]

    assert result["counts"]["Agent"] == 1
    with temp_db.session_scope() as session:
        agents = session.exec(select(models.Agent)).all()
        assert any(a.agent_id == "live-agent" for a in agents)


def test_load_targets_from_example_fixture():
    targets = targets_mod.load_targets(FIXTURES_DIR / "targets.example.yml")
    platforms = {t.platform for t in targets}
    assert {"generic_http", "dify", "azure_openai", "bedrock", "mcp"} <= platforms
    assert all(t.enabled is False for t in targets)  # example is disabled by default


def test_otlp_http_receiver_ingests_and_assess(temp_db):
    from agentic_ai_exposure_assessor import app as appmod

    doc = json.loads((FIXTURES_DIR / "otlp_trace_sample.json").read_text(encoding="utf-8"))
    with TestClient(appmod.app) as client:
        resp = client.post("/v1/traces", json=doc)
        assert resp.status_code == 200
        body = resp.json()
        assert "partialSuccess" in body
        assert body["ingested"]["RuntimeToolCall"] >= 4

    with temp_db.session_scope() as session:
        calls = session.exec(select(models.RuntimeToolCall)).all()
        assert {c.tool_name for c in calls} >= {"send_email", "run_shell"}


def test_otlp_http_receiver_rejects_non_json(temp_db):
    from agentic_ai_exposure_assessor import app as appmod

    with TestClient(appmod.app) as client:
        resp = client.post("/v1/traces", content="not json", headers={"content-type": "text/plain"})
        assert resp.status_code == 415
