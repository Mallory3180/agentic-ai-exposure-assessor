"""Tests for the rule engine, scoring and redaction."""

from __future__ import annotations

from agentic_ai_exposure_assessor import (
    config_loader,
    redaction,
    risk_engine,
    scoring,
    trace_ingest,
)


def _seed(temp_db, fixtures_dir):
    with temp_db.session_scope() as session:
        config_loader.load_directory(fixtures_dir, session)
        trace_ingest.ingest_file(fixtures_dir / "otlp_trace_sample.json", session)
    with temp_db.session_scope() as session:
        return risk_engine.assess(session, run_name="test-run")


def _finding_rule_ids(temp_db):
    from sqlmodel import select

    from agentic_ai_exposure_assessor import models

    with temp_db.session_scope() as session:
        findings = session.exec(select(models.Finding)).all()
        return [f.rule_id for f in findings], list(findings)


def test_assess_produces_findings(temp_db, fixtures_dir):
    run = _seed(temp_db, fixtures_dir)
    assert run.total_findings > 0
    assert run.risk_score > 0
    assert run.owasp_counts  # at least one OWASP category populated


def test_unknown_tool_finding(temp_db, fixtures_dir):
    _seed(temp_db, fixtures_dir)
    rule_ids, _ = _finding_rule_ids(temp_db)
    assert "ASI02-002" in rule_ids  # exfiltrate_data is unknown


def test_unknown_agent_finding(temp_db, fixtures_dir):
    _seed(temp_db, fixtures_dir)
    rule_ids, findings = _finding_rule_ids(temp_db)
    assert "ASI10-001" in rule_ids
    assert any(f.affected_agent == "rogue-agent" for f in findings if f.rule_id == "ASI10-001")


def test_approval_missing_finding(temp_db, fixtures_dir):
    _seed(temp_db, fixtures_dir)
    rule_ids, findings = _finding_rule_ids(temp_db)
    assert "ASI09-001" in rule_ids
    affected = {f.affected_tool for f in findings if f.rule_id == "ASI09-001"}
    assert "send_email" in affected or "run_shell" in affected


def test_code_exec_and_scope_findings(temp_db, fixtures_dir):
    _seed(temp_db, fixtures_dir)
    rule_ids, _ = _finding_rule_ids(temp_db)
    assert "ASI05-001" in rule_ids  # run_shell without approval
    assert "ASI03-003" in rule_ids  # db.admin scope not allowed
    assert "ASI07-001" in rule_ids  # message without TLS
    assert "ASI10-002" in rule_ids  # legacy-batch-agent without owner


def test_risk_score_and_severity():
    assert scoring.risk_score(5, 5, 5) == 125
    assert scoring.severity_for(125) == "critical"
    assert scoring.severity_for(1) == "info"
    assert scoring.clamp(9) == 5


def test_redaction_masks_secrets():
    text = "authorization: Bearer sk-ABCDEF1234567890abcdef and password=hunter2value"
    out = redaction.redact_text(text)
    assert "sk-ABCDEF1234567890abcdef" not in out
    assert "hunter2value" not in out
    assert redaction.MASK in out


def test_redaction_value_recurses_sensitive_key():
    data = {"api_key": "longsecretvalue123", "nested": {"token": "anothersecret999"}}
    out = redaction.redact_value(data)
    assert out["api_key"] == redaction.MASK
    assert out["nested"]["token"] == redaction.MASK


def test_summarize_truncates_and_redacts():
    raw = "password=supersecretvalue " + ("x" * 500)
    summary = redaction.summarize(raw, limit=50)
    assert "supersecretvalue" not in summary
    assert len(summary) <= 80
