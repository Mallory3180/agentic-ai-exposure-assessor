"""Tests for real-telemetry adapters (Jaeger / LangSmith / OTLP NDJSON) — the A-1 path."""

from __future__ import annotations

import json

from agentic_ai_exposure_assessor import trace_adapters


def test_detect_format():
    assert trace_adapters.detect_format({"resourceSpans": []}) == "otlp"
    assert trace_adapters.detect_format({"data": [{"spans": []}]}) == "jaeger"
    ls_doc = [{"run_type": "tool", "id": "1", "inputs": {}}]
    assert trace_adapters.detect_format(ls_doc) == "langsmith"
    assert trace_adapters.detect_format({"spans": []}) == "simplified"


def test_jaeger_adapter_normalizes_tool_call():
    doc = {
        "data": [
            {
                "traceID": "jt1",
                "processes": {"p1": {"serviceName": "unrestricted-bash-agent"}},
                "spans": [
                    {
                        "traceID": "jt1",
                        "spanID": "s1",
                        "operationName": "execute_command",
                        "processID": "p1",
                        "startTime": 1718700000000000,
                        "duration": 1000000,
                        "references": [],
                        "tags": [
                            {"key": "openinference.span.kind", "type": "string", "value": "TOOL"},
                            {"key": "tool.name", "type": "string", "value": "execute_command"},
                            {"key": "input.value", "type": "string", "value": '{"command": "ls"}'},
                            {"key": "credential.scope", "type": "string", "value": "shell.exec"},
                        ],
                    }
                ],
            }
        ]
    }
    trace = trace_adapters.trace_ingest.normalize_document(trace_adapters.to_otlp_document(doc))
    assert len(trace.tool_calls) == 1
    call = trace.tool_calls[0]
    assert call.tool_name == "execute_command"
    assert call.agent_name == "unrestricted-bash-agent"
    assert call.arguments == {"command": "ls"}
    assert call.credential_scope == "shell.exec"


def test_langsmith_adapter_normalizes_runs():
    runs = [
        {
            "id": "r-llm",
            "run_type": "llm",
            "name": "ChatOpenAI",
            "trace_id": "lt1",
            "start_time": "2026-01-01T00:00:00Z",
            "extra": {"invocation_params": {"model": "gpt-4o"}},
        },
        {
            "id": "r-tool",
            "run_type": "tool",
            "name": "run_cypher",
            "trace_id": "lt1",
            "parent_run_id": "r-llm",
            "start_time": "2026-01-01T00:00:01Z",
            "inputs": {"query": "MATCH (n) DETACH DELETE n"},
            "outputs": {"result": "ok"},
            "extra": {"metadata": {"langgraph_node": "db_node", "credential.scope": "graph.write"}},
        },
    ]
    trace = trace_adapters.trace_ingest.normalize_document(
        trace_adapters.to_otlp_document(runs)
    )
    tools = {c.tool_name: c for c in trace.tool_calls}
    assert "run_cypher" in tools
    assert tools["run_cypher"].arguments == {"query": "MATCH (n) DETACH DELETE n"}
    # Metadata signals pass through.
    assert tools["run_cypher"].credential_scope == "graph.write"


def test_otlp_ndjson_file(tmp_path):
    """OTel Collector 'file' exporter writes one ExportTraceServiceRequest per line."""
    line = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [{"key": "service.name", "value": {"stringValue": "a"}}]
                },
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "traceId": "n1",
                                "spanId": "s1",
                                "name": "send_email",
                                "startTimeUnixNano": "1",
                                "endTimeUnixNano": "2",
                                "attributes": [
                                    {"key": "tool.name", "value": {"stringValue": "send_email"}}
                                ],
                            }
                        ]
                    }
                ],
            }
        ]
    }
    path = tmp_path / "otel_file_export.ndjson"
    path.write_text(json.dumps(line) + "\n" + json.dumps(line) + "\n", encoding="utf-8")
    trace = trace_adapters.load_trace_any(path, fmt="auto")
    # Two lines -> two spans -> two tool calls.
    assert len(trace.tool_calls) == 2


def test_unknown_format_raises():
    try:
        trace_adapters.detect_format(12345)
    except trace_adapters.AdapterError:
        return
    raise AssertionError("expected AdapterError")
