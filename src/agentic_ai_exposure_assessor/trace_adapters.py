"""Adapters that turn *real* exported telemetry into the assessor's trace model (A-1).

The receiver and ``ingest-otlp`` already accept native OTLP/JSON. Real engagements, however,
produce telemetry in several shapes. This module converts the common ones into the flat
span structure that :func:`trace_ingest.normalize_document` understands, so all downstream
logic (tool detection, OpenInference mapping, rules) is reused unchanged.

Supported sources (auto-detected):

* ``otlp``        — native OTLP/JSON (``resourceSpans``), incl. the OTel Collector ``file``
                    exporter. NDJSON (one ``ExportTraceServiceRequest`` per line) is merged.
* ``jaeger``      — Jaeger query API JSON (``{"data": [{"spans": [...], "processes": {...}}]}``).
* ``langsmith``   — LangSmith *runs* export (a list of run objects, or ``{"runs": [...]}``).
* ``simplified``  — the tool's own flat ``{"spans": [...]}`` shape.

Customers can carry assessor-specific signals (approval.status, credential.scope,
tls.protocol.name, memory.operation, source.trust, ...) as Jaeger **tags** or LangSmith
**metadata**; those are merged into span attributes verbatim.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from . import trace_ingest
from .trace_ingest import NormalizedTrace, TraceIngestError

SUPPORTED_FORMATS = ("auto", "otlp", "jaeger", "langsmith", "simplified")

# Run types that should surface as tool calls in LangSmith exports.
_LANGSMITH_TOOL_TYPES = {"tool", "retriever"}


class AdapterError(TraceIngestError):
    """Raised when telemetry cannot be read or converted."""


# --------------------------------------------------------------------------- #
# Raw loading (JSON or NDJSON)                                                 #
# --------------------------------------------------------------------------- #
def _load_raw(path: Path) -> Any:
    """Load a JSON document, or a list of documents for NDJSON (JSON-lines)."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise AdapterError(f"Trace file not found: {path}") from exc
    text = text.strip()
    if not text:
        raise AdapterError(f"Trace file is empty: {path}")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # NDJSON: parse each non-empty line.
    docs: list[Any] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            docs.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise AdapterError(
                f"{path}: not valid JSON or NDJSON (line {lineno}): {exc}"
            ) from exc
    if not docs:
        raise AdapterError(f"{path}: no JSON content found")
    return docs


def _merge_ndjson(docs: list[Any]) -> Any:
    """Merge a list of parsed documents (NDJSON) into one document.

    If every item is an OTLP request, concatenate their resourceSpans. Otherwise, if items
    are spans/runs, return the list as-is for format detection.
    """
    if all(isinstance(d, dict) and "resourceSpans" in d for d in docs):
        merged: list[Any] = []
        for d in docs:
            merged.extend(d.get("resourceSpans", []))
        return {"resourceSpans": merged}
    # Flatten list-of-lists (e.g. NDJSON of run arrays).
    flat: list[Any] = []
    for d in docs:
        if isinstance(d, list):
            flat.extend(d)
        else:
            flat.append(d)
    return flat


# --------------------------------------------------------------------------- #
# Format detection                                                            #
# --------------------------------------------------------------------------- #
def detect_format(doc: Any) -> str:
    """Best-effort detection of the telemetry format."""
    if isinstance(doc, dict):
        if "resourceSpans" in doc:
            return "otlp"
        if "data" in doc and isinstance(doc["data"], list):
            first = doc["data"][0] if doc["data"] else {}
            if isinstance(first, dict) and ("spans" in first or "traceID" in first):
                return "jaeger"
        if "runs" in doc and isinstance(doc["runs"], list):
            return "langsmith"
        if "spans" in doc:
            return "simplified"
    if isinstance(doc, list) and doc:
        first = doc[0]
        if isinstance(first, dict):
            if "run_type" in first or ("inputs" in first and "id" in first):
                return "langsmith"
            if "operationName" in first or "spanID" in first:
                return "jaeger"
            return "simplified"
    raise AdapterError(
        "Could not auto-detect telemetry format. Pass an explicit --format "
        f"(one of {', '.join(f for f in SUPPORTED_FORMATS if f != 'auto')})."
    )


# --------------------------------------------------------------------------- #
# Jaeger adapter                                                              #
# --------------------------------------------------------------------------- #
def jaeger_to_spans(doc: Any) -> dict[str, Any]:
    """Convert Jaeger query-API JSON into the simplified ``{"spans": [...]}`` shape."""
    traces = doc.get("data", []) if isinstance(doc, dict) else doc
    spans_out: list[dict[str, Any]] = []
    for trace in traces or []:
        processes = trace.get("processes", {}) if isinstance(trace, dict) else {}
        for span in trace.get("spans", []) if isinstance(trace, dict) else []:
            attrs: dict[str, Any] = {}
            for tag in span.get("tags", []):
                if isinstance(tag, dict) and "key" in tag:
                    attrs[str(tag["key"])] = tag.get("value")
            proc = processes.get(span.get("processID", ""), {})
            service = proc.get("serviceName") if isinstance(proc, dict) else None
            if service and "service.name" not in attrs:
                attrs["service.name"] = service

            parent = ""
            for ref in span.get("references", []):
                if isinstance(ref, dict) and ref.get("refType") == "CHILD_OF":
                    parent = str(ref.get("spanID", ""))
                    break

            start_us = span.get("startTime", 0)  # microseconds
            dur_us = span.get("duration", 0)
            start_ns = int(start_us) * 1000 if start_us else ""
            end_ns = (int(start_us) + int(dur_us)) * 1000 if start_us else ""

            status = "OK"
            if attrs.get("error") in (True, "true") or attrs.get("otel.status_code") == "ERROR":
                status = "ERROR"

            spans_out.append(
                {
                    "trace_id": str(span.get("traceID", "")),
                    "span_id": str(span.get("spanID", "")),
                    "parent_span_id": parent,
                    "name": span.get("operationName", ""),
                    "kind": str(span.get("kind", "")),
                    "start_time": str(start_ns),
                    "end_time": str(end_ns),
                    "status": status,
                    "attributes": attrs,
                    "events": [],
                }
            )
    return {"spans": spans_out}


# --------------------------------------------------------------------------- #
# LangSmith adapter                                                           #
# --------------------------------------------------------------------------- #
def _iso_to_nanos(value: Any) -> str:
    if not value:
        return ""
    try:
        text = str(value).replace("Z", "+00:00")
        return str(int(datetime.fromisoformat(text).timestamp() * 1_000_000_000))
    except (ValueError, TypeError):
        return ""


def _as_json_str(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def langsmith_to_spans(doc: Any) -> dict[str, Any]:
    """Convert a LangSmith runs export into the simplified ``{"spans": [...]}`` shape."""
    runs = doc.get("runs", []) if isinstance(doc, dict) else doc
    spans_out: list[dict[str, Any]] = []
    for run in runs or []:
        if not isinstance(run, dict):
            continue
        run_type = str(run.get("run_type", "")).lower()
        extra = run.get("extra", {}) if isinstance(run.get("extra"), dict) else {}
        metadata = extra.get("metadata", {}) if isinstance(extra.get("metadata"), dict) else {}

        attrs: dict[str, Any] = {}
        # Pass through any assessor-relevant signals the customer set as metadata.
        for key, value in metadata.items():
            attrs[str(key)] = value
        if metadata.get("langgraph_node") and "langgraph.node" not in attrs:
            attrs["langgraph.node"] = metadata["langgraph_node"]

        name = run.get("name", "")
        if run_type in _LANGSMITH_TOOL_TYPES:
            attrs.setdefault("openinference.span.kind", "TOOL")
            attrs.setdefault("tool.name", name)
            attrs.setdefault("input.value", _as_json_str(run.get("inputs")))
            attrs.setdefault("output.value", _as_json_str(run.get("outputs")))
        elif run_type == "llm":
            attrs.setdefault("openinference.span.kind", "LLM")
            model = (extra.get("invocation_params", {}) or {}).get("model")
            if model:
                attrs.setdefault("gen_ai.request.model", model)
                attrs.setdefault("llm.model_name", model)

        status = "ERROR" if run.get("error") else "OK"
        spans_out.append(
            {
                "trace_id": str(run.get("trace_id") or run.get("session_id") or run.get("id", "")),
                "span_id": str(run.get("id", "")),
                "parent_span_id": str(run.get("parent_run_id") or ""),
                "name": name,
                "kind": "",
                "start_time": _iso_to_nanos(run.get("start_time")),
                "end_time": _iso_to_nanos(run.get("end_time")),
                "status": status,
                "attributes": attrs,
                "events": [],
            }
        )
    return {"spans": spans_out}


# --------------------------------------------------------------------------- #
# Public entry points                                                         #
# --------------------------------------------------------------------------- #
def to_otlp_document(doc: Any, fmt: str = "auto") -> Any:
    """Convert any supported telemetry document into a normalize-ready document."""
    if fmt == "auto":
        fmt = detect_format(doc)
    if fmt == "otlp" or fmt == "simplified":
        return doc
    if fmt == "jaeger":
        return jaeger_to_spans(doc)
    if fmt == "langsmith":
        return langsmith_to_spans(doc)
    raise AdapterError(f"Unsupported format: {fmt!r} (use one of {SUPPORTED_FORMATS})")


def load_trace_any(path: Path, fmt: str = "auto") -> NormalizedTrace:
    """Read + convert + normalize a telemetry file of any supported format."""
    if fmt not in SUPPORTED_FORMATS:
        raise AdapterError(f"Unsupported format: {fmt!r} (use one of {SUPPORTED_FORMATS})")
    raw = _load_raw(path)
    if isinstance(raw, list) and raw and all(
        isinstance(d, dict) and ("resourceSpans" in d or "data" in d or "runs" in d) for d in raw
    ):
        raw = _merge_ndjson(raw)
    doc = to_otlp_document(raw, fmt)
    return trace_ingest.normalize_document(doc)
