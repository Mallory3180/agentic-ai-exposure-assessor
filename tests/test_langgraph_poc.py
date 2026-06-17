"""Tests for LangGraph/OpenInference trace support and the GenAI-Security-Initiative PoC."""

from __future__ import annotations

from pathlib import Path

from sqlmodel import select

from agentic_ai_exposure_assessor import config_loader, models, risk_engine, trace_ingest

REPO_ROOT = Path(__file__).resolve().parents[1]
POC_DIR = REPO_ROOT / "examples" / "genai_agent_security_initiative"


def test_openinference_tool_span_is_normalized():
    """A LangChain/LangGraph OpenInference TOOL span maps to a RuntimeToolCall."""
    doc = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "my-agent"}}
                    ]
                },
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "traceId": "t1",
                                "spanId": "s1",
                                "name": "execute_command",
                                "startTimeUnixNano": "1",
                                "endTimeUnixNano": "2",
                                "status": {"code": "STATUS_CODE_OK"},
                                "attributes": [
                                    {
                                        "key": "openinference.span.kind",
                                        "value": {"stringValue": "TOOL"},
                                    },
                                    {"key": "langgraph.node", "value": {"stringValue": "node_a"}},
                                    {
                                        "key": "tool.name",
                                        "value": {"stringValue": "execute_command"},
                                    },
                                    {
                                        "key": "input.value",
                                        "value": {"stringValue": '{"command": "ls -la"}'},
                                    },
                                    {"key": "output.value", "value": {"stringValue": "files..."}},
                                ],
                            }
                        ]
                    }
                ],
            }
        ]
    }
    trace = trace_ingest.normalize_document(doc)
    assert len(trace.tool_calls) == 1
    call = trace.tool_calls[0]
    assert call.tool_name == "execute_command"
    # service.name wins over langgraph.node for agent identity.
    assert call.agent_name == "my-agent"
    # arguments come from input.value when tool.arguments is absent.
    assert call.arguments == {"command": "ls -la"}


def test_tool_span_without_tool_name_uses_span_name():
    doc = {
        "spans": [
            {
                "trace_id": "t2",
                "span_id": "s2",
                "name": "run_cypher",
                "attributes": {
                    "service.name": "db-agent",
                    "openinference.span.kind": "TOOL",
                    "input.value": '{"query": "MATCH (n) RETURN n"}',
                },
            }
        ]
    }
    trace = trace_ingest.normalize_document(doc)
    assert [c.tool_name for c in trace.tool_calls] == ["run_cypher"]


def test_poc_inventory_and_trace_files_present():
    assert (POC_DIR / "inventory" / "agent_inventory.yml").exists()
    assert (POC_DIR / "langgraph_trace.json").exists()


def _seed_poc(temp_db):
    with temp_db.session_scope() as session:
        config_loader.load_directory(POC_DIR / "inventory", session)
        trace_ingest.ingest_file(POC_DIR / "langgraph_trace.json", session)
    with temp_db.session_scope() as session:
        risk_engine.assess(session, run_name="poc")


def test_poc_assessment_findings(temp_db):
    _seed_poc(temp_db)
    with temp_db.session_scope() as session:
        findings = session.exec(select(models.Finding)).all()
    rule_ids = {f.rule_id for f in findings}
    # Core findings expected from the LangGraph insecure samples.
    for expected in ("ASI05-001", "ASI09-001", "ASI03-003", "ASI03-001", "ASI06-001", "ASI07-001"):
        assert expected in rule_ids, f"missing {expected}; got {sorted(rule_ids)}"

    # The bash RCE finding must be attributed to the right LangGraph agent (not a node).
    bash = [
        f
        for f in findings
        if f.rule_id == "ASI05-001" and f.affected_tool == "execute_command"
    ]
    assert bash and bash[0].affected_agent == "unrestricted-bash-agent"

    # No spurious unknown-agent findings (agents resolve via service.name).
    assert "ASI10-001" not in rule_ids
