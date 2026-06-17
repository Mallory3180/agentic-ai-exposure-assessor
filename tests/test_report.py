"""Tests for report generation and the README/CLI contract."""

from __future__ import annotations

import re
from pathlib import Path

from agentic_ai_exposure_assessor import config_loader, report, risk_engine, trace_ingest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _seed_and_assess(temp_db, fixtures_dir):
    with temp_db.session_scope() as session:
        config_loader.load_directory(fixtures_dir, session)
        trace_ingest.ingest_file(fixtures_dir / "otlp_trace_sample.json", session)
    with temp_db.session_scope() as session:
        risk_engine.assess(session, run_name="report-test")


def test_markdown_report_has_required_chapters(temp_db, fixtures_dir):
    _seed_and_assess(temp_db, fixtures_dir)
    with temp_db.session_scope() as session:
        data = report.build_report_data(session)
        md = report.render_markdown(data)
    for chapter in [
        "## 1. Executive Summary",
        "## 2. Scope",
        "## 3. Agent Inventory",
        "## 4. Tool and Permission Matrix",
        "## 5. Runtime Trace Analysis",
        "## 6. Approval Gate Analysis",
        "## 7. OWASP Agentic AI Top 10 Risk Mapping",
        "## 8. Findings",
        "## 9. Recommendations",
        "## 10. Appendix: Evidence",
    ]:
        assert chapter in md
    assert "```mermaid" in md


def test_export_writes_all_formats(temp_db, fixtures_dir, tmp_path):
    _seed_and_assess(temp_db, fixtures_dir)
    with temp_db.session_scope() as session:
        md_path = report.export(session, "markdown", tmp_path / "out" / "report.md")
        json_path = report.export(session, "json", tmp_path / "out" / "report.json")
        html_path = report.export(session, "html", tmp_path / "out" / "report.html")
    assert md_path.exists() and md_path.read_text(encoding="utf-8")
    assert json_path.exists() and json_path.read_text(encoding="utf-8").startswith("{")
    assert "<html" in html_path.read_text(encoding="utf-8").lower()


def test_report_redacts_secrets(temp_db, fixtures_dir, tmp_path):
    # Inject a tool call carrying a secret to ensure it is redacted in the report.
    from agentic_ai_exposure_assessor import models

    with temp_db.session_scope() as session:
        config_loader.load_directory(fixtures_dir, session)
        session.add(
            models.RuntimeToolCall(
                trace_id="t-secret",
                span_id="s1",
                agent_name="customer-support-agent",
                tool_name="send_email",
                arguments={"authorization": "Bearer sk-SECRET1234567890abcd"},
            )
        )
    with temp_db.session_scope() as session:
        risk_engine.assess(session, run_name="secret-test")
    with temp_db.session_scope() as session:
        json_path = report.export(session, "json", tmp_path / "report.json")
    content = json_path.read_text(encoding="utf-8")
    assert "sk-SECRET1234567890abcd" not in content


def test_readme_commands_are_consistent():
    """Every CLI subcommand referenced in the README must exist in the Typer app."""
    from agentic_ai_exposure_assessor import cli

    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    referenced = set(re.findall(r"cli\s+([a-z][a-z\-]+)", readme))
    registered = {c.name for c in cli.app.registered_commands}
    missing = referenced - registered
    assert not missing, f"README references unknown CLI commands: {missing}"
    # Sanity: the documented core commands are all present.
    assert {
        "init-fixtures",
        "ingest-config",
        "ingest-otlp",
        "assess",
        "export-report",
        "serve",
    } <= registered
