"""Tests for OTLP trace ingestion and normalization."""

from __future__ import annotations

from agentic_ai_exposure_assessor import trace_ingest


def test_normalize_otlp_sample(fixtures_dir):
    trace = trace_ingest.load_trace_file(fixtures_dir / "otlp_trace_sample.json")
    assert trace.spans, "expected spans"
    tool_names = {c.tool_name for c in trace.tool_calls}
    assert {"send_email", "run_shell", "read_file", "exfiltrate_data"} <= tool_names


def test_tool_call_sequence_is_ordered(fixtures_dir):
    trace = trace_ingest.load_trace_file(fixtures_dir / "otlp_trace_sample.json")
    sequences = trace.sequences()
    trace_id = next(iter(sequences))
    indices = [c.sequence_index for c in sequences[trace_id]]
    assert indices == sorted(indices)
    # send_email starts first in the sample.
    assert sequences[trace_id][0].tool_name == "send_email"


def test_approval_detected(fixtures_dir):
    trace = trace_ingest.load_trace_file(fixtures_dir / "otlp_trace_sample.json")
    send_email = next(c for c in trace.tool_calls if c.tool_name == "send_email")
    assert send_email.approval_observed is False
    assert send_email.approval_status.lower() in {"skipped", "approval.skipped"}


def test_windows_paths_in_arguments(fixtures_dir):
    trace = trace_ingest.load_trace_file(fixtures_dir / "otlp_trace_sample.json")
    run_shell = next(c for c in trace.tool_calls if c.tool_name == "run_shell")
    blob = str(run_shell.arguments)
    assert "C:" in blob and ("\\\\" in blob or "\\" in blob or "Users" in blob)
    read_file = next(c for c in trace.tool_calls if c.tool_name == "read_file")
    assert "C:/Users/diag/Downloads/sample.txt" in str(read_file.arguments)


def test_inter_agent_and_memory_normalized(fixtures_dir):
    trace = trace_ingest.load_trace_file(fixtures_dir / "otlp_trace_sample.json")
    assert any(not m.tls_observed for m in trace.messages)
    assert any(m.tls_observed for m in trace.messages)
    assert any(
        op.operation == "write" and op.source_trust == "untrusted" for op in trace.memory_ops
    )


def test_simplified_flat_format(fixtures_dir):
    trace = trace_ingest.load_trace_file(fixtures_dir / "promptfoo_eval_sample.json")
    assert {c.tool_name for c in trace.tool_calls} == {"send_email", "search_customer"}
    approved = next(c for c in trace.tool_calls if c.tool_name == "send_email")
    assert approved.approval_observed is True


def test_invalid_json_raises(tmp_path):
    bad = tmp_path / "trace.json"
    bad.write_text("{not valid json", encoding="utf-8")
    try:
        trace_ingest.load_trace_file(bad)
    except trace_ingest.TraceIngestError:
        return
    raise AssertionError("expected TraceIngestError")
