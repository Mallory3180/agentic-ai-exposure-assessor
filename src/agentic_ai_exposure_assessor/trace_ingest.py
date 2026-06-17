"""OTLP-style trace ingestion and normalization.

Reads an OTLP / Jaeger / Promptfoo-export style JSON trace file and normalizes it into:

* :class:`~.models.RuntimeSpan`         — one per span (with a flattened attribute dict)
* :class:`~.models.RuntimeToolCall`     — one per tool / function / MCP-tool invocation
* :class:`~.models.InterAgentMessage`   — one per agent-to-agent message
* :class:`~.models.MemoryOperation`     — one per memory/RAG read or write

Two input shapes are supported:

1. **Native OTLP JSON** — ``{"resourceSpans": [{"resource": {...},
   "scopeSpans": [{"spans": [...]}]}]}`` where attribute values are typed objects
   (``{"stringValue": "..."}``).
2. **Simplified JSON** — either a bare list of spans, or ``{"spans": [...]}`` where each
   span carries a plain ``attributes`` dict.

All free-form text (tool output, rag query) is summarized + redacted before storage. The
parser is tolerant of Windows path strings inside arguments (``C:\\Users\\...``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlmodel import Session

from . import models, redaction


class TraceIngestError(Exception):
    """Raised when a trace file cannot be read or parsed."""


# --------------------------------------------------------------------------- #
# Low level helpers                                                            #
# --------------------------------------------------------------------------- #
def _coerce_otlp_value(value: Any) -> Any:
    """Convert an OTLP typed attribute value object into a plain Python value."""
    if not isinstance(value, dict):
        return value
    if "stringValue" in value:
        return value["stringValue"]
    if "boolValue" in value:
        return bool(value["boolValue"])
    if "intValue" in value:
        try:
            return int(value["intValue"])
        except (TypeError, ValueError):
            return value["intValue"]
    if "doubleValue" in value:
        return float(value["doubleValue"])
    if "arrayValue" in value:
        items = value["arrayValue"].get("values", [])
        return [_coerce_otlp_value(v) for v in items]
    if "kvlistValue" in value:
        return _attrs_to_dict(value["kvlistValue"].get("values", []))
    return value


def _attrs_to_dict(attributes: Any) -> dict[str, Any]:
    """Flatten an attribute list/dict into a plain ``{key: value}`` mapping."""
    result: dict[str, Any] = {}
    if isinstance(attributes, dict):
        # Already flat (simplified format).
        return dict(attributes)
    if isinstance(attributes, list):
        for item in attributes:
            if not isinstance(item, dict) or "key" not in item:
                continue
            result[item["key"]] = _coerce_otlp_value(item.get("value"))
    return result


def _maybe_json(value: Any) -> Any:
    """Parse a string that looks like JSON, otherwise return it unchanged."""
    if isinstance(value, str):
        stripped = value.strip()
        if stripped[:1] in "{[":
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                return value
    return value


def _as_arguments(value: Any) -> dict[str, Any]:
    """Normalize a tool's arguments into a dict."""
    parsed = _maybe_json(value)
    if isinstance(parsed, dict):
        return parsed
    if parsed in (None, ""):
        return {}
    return {"value": parsed}


def _nano_to_ms(start: Any, end: Any) -> float:
    try:
        return max(0.0, (float(end) - float(start)) / 1_000_000.0)
    except (TypeError, ValueError):
        return 0.0


def _sort_key(start: Any, fallback: int) -> tuple[float, int]:
    try:
        return (float(start), fallback)
    except (TypeError, ValueError):
        return (float(fallback), fallback)


def _status_str(status: Any) -> str:
    if isinstance(status, dict):
        code = status.get("code", status.get("status_code", "UNSET"))
        return str(code)
    return str(status) if status not in (None, "") else "UNSET"


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "required", "required=true"}
    return False


# --------------------------------------------------------------------------- #
# Raw span extraction                                                          #
# --------------------------------------------------------------------------- #
def _iter_raw_spans(doc: Any) -> list[dict[str, Any]]:
    """Yield ``(span_dict, resource_attrs)`` merged into normalized raw span dicts."""
    spans: list[dict[str, Any]] = []

    if isinstance(doc, dict) and "resourceSpans" in doc:
        for resource_span in doc.get("resourceSpans", []):
            resource = resource_span.get("resource", {})
            resource_attrs = _attrs_to_dict(resource.get("attributes", []))
            for scope_span in resource_span.get("scopeSpans", []):
                for span in scope_span.get("spans", []):
                    spans.append(_normalize_otlp_span(span, resource_attrs))
        return spans

    raw_list: list[Any]
    if isinstance(doc, list):
        raw_list = doc
    elif isinstance(doc, dict) and "spans" in doc:
        raw_list = doc["spans"]
    else:
        raise TraceIngestError(
            "Unrecognized trace format: expected 'resourceSpans', a 'spans' list, "
            "or a bare list of spans."
        )

    for span in raw_list:
        if isinstance(span, dict):
            spans.append(_normalize_simplified_span(span))
    return spans


def _normalize_otlp_span(span: dict[str, Any], resource_attrs: dict[str, Any]) -> dict[str, Any]:
    attrs = dict(resource_attrs)
    attrs.update(_attrs_to_dict(span.get("attributes", [])))
    events = []
    for event in span.get("events", []):
        events.append(
            {
                "name": event.get("name", ""),
                "time": event.get("timeUnixNano", event.get("time", "")),
                "attributes": _attrs_to_dict(event.get("attributes", [])),
            }
        )
    start = span.get("startTimeUnixNano", span.get("start_time", ""))
    end = span.get("endTimeUnixNano", span.get("end_time", ""))
    return {
        "trace_id": str(span.get("traceId", span.get("trace_id", ""))),
        "span_id": str(span.get("spanId", span.get("span_id", ""))),
        "parent_span_id": str(span.get("parentSpanId", span.get("parent_span_id", ""))),
        "name": span.get("name", ""),
        "kind": str(span.get("kind", "")),
        "start_time": str(start),
        "end_time": str(end),
        "duration_ms": _nano_to_ms(start, end),
        "status": _status_str(span.get("status")),
        "attributes": attrs,
        "events": events,
    }


def _normalize_simplified_span(span: dict[str, Any]) -> dict[str, Any]:
    attrs = _attrs_to_dict(span.get("attributes", {}))
    events = span.get("events", []) or []
    norm_events = []
    for event in events:
        if isinstance(event, dict):
            norm_events.append(
                {
                    "name": event.get("name", ""),
                    "time": event.get("time", ""),
                    "attributes": _attrs_to_dict(event.get("attributes", {})),
                }
            )
    start = span.get("start_time", span.get("startTimeUnixNano", ""))
    end = span.get("end_time", span.get("endTimeUnixNano", ""))
    return {
        "trace_id": str(span.get("trace_id", span.get("traceId", ""))),
        "span_id": str(span.get("span_id", span.get("spanId", ""))),
        "parent_span_id": str(span.get("parent_span_id", span.get("parentSpanId", ""))),
        "name": span.get("name", ""),
        "kind": str(span.get("kind", "")),
        "start_time": str(start),
        "end_time": str(end),
        "duration_ms": float(span.get("duration_ms", _nano_to_ms(start, end)) or 0.0),
        "status": _status_str(span.get("status")),
        "attributes": attrs,
        "events": norm_events,
    }


# --------------------------------------------------------------------------- #
# Normalization to domain objects                                             #
# --------------------------------------------------------------------------- #
def _agent_name(attrs: dict[str, Any], span_name: str) -> str:
    for key in ("agent.name", "agent.id", "gen_ai.agent.name", "service.name"):
        value = attrs.get(key)
        if value:
            return str(value)
    return span_name or "unknown-agent"


def _detect_approval(attrs: dict[str, Any], events: list[dict[str, Any]]) -> tuple[bool, str]:
    """Return ``(approval_observed, approval_status)``."""
    status = str(attrs.get("approval.status", "")).strip()
    observed = status.lower() == "approved"
    for event in events:
        name = str(event.get("name", "")).lower()
        ev_attrs = event.get("attributes", {})
        ev_status = str(ev_attrs.get("approval.status", "")).strip()
        if ev_status:
            status = ev_status
        if "approv" in name and (name.endswith("approved") or ev_status.lower() == "approved"):
            observed = True
        if any(token in name for token in ("skipped", "timeout", "bypass", "denied")):
            observed = False
            if not status:
                status = name
    return observed, status


def _detect_tls(attrs: dict[str, Any]) -> bool:
    return bool(
        attrs.get("tls.protocol.name") or attrs.get("tls.cipher") or attrs.get("tls.version")
    )


class NormalizedTrace:
    """Container for the objects produced from a single trace file."""

    def __init__(self) -> None:
        self.spans: list[models.RuntimeSpan] = []
        self.tool_calls: list[models.RuntimeToolCall] = []
        self.messages: list[models.InterAgentMessage] = []
        self.memory_ops: list[models.MemoryOperation] = []

    def sequences(self) -> dict[str, list[models.RuntimeToolCall]]:
        """Group tool calls into per-trace ordered sequences."""
        grouped: dict[str, list[models.RuntimeToolCall]] = {}
        for call in self.tool_calls:
            grouped.setdefault(call.trace_id, []).append(call)
        for calls in grouped.values():
            calls.sort(key=lambda c: c.sequence_index)
        return grouped


def normalize_document(doc: Any) -> NormalizedTrace:
    """Normalize a parsed trace document into domain objects."""
    raw_spans = _iter_raw_spans(doc)
    # Establish a stable ordering across all spans by start time.
    ordered = sorted(
        enumerate(raw_spans), key=lambda pair: _sort_key(pair[1]["start_time"], pair[0])
    )

    result = NormalizedTrace()
    seq_counters: dict[str, int] = {}

    for _, raw in ordered:
        attrs = raw["attributes"]
        events = raw["events"]
        result.spans.append(models.RuntimeSpan(**raw))

        agent = _agent_name(attrs, raw["name"])

        # ---- Tool / function / MCP-tool call ---------------------------------
        tool_name = (
            attrs.get("tool.name")
            or attrs.get("mcp.tool.name")
            or attrs.get("function.name")
        )
        if tool_name:
            approval_observed, approval_status = _detect_approval(attrs, events)
            seq = seq_counters.get(raw["trace_id"], 0)
            seq_counters[raw["trace_id"]] = seq + 1
            result.tool_calls.append(
                models.RuntimeToolCall(
                    trace_id=raw["trace_id"],
                    span_id=raw["span_id"],
                    sequence_index=seq,
                    agent_name=agent,
                    tool_name=str(tool_name),
                    arguments=redaction.redact_value(
                        _as_arguments(attrs.get("tool.arguments"))
                    ),
                    output_summary=redaction.summarize(attrs.get("tool.output")),
                    status=raw["status"],
                    approval_observed=approval_observed,
                    approval_status=approval_status,
                    credential_scope=str(
                        attrs.get("credential.scope", attrs.get("auth.scope", ""))
                    ),
                    network_peer=str(attrs.get("network.peer.address", "")),
                    network_port=str(attrs.get("network.peer.port", "")),
                    tls_observed=_detect_tls(attrs),
                    mcp_server=str(attrs.get("mcp.server.name", "")),
                    timestamp=raw["start_time"],
                )
            )

        # ---- Inter-agent message --------------------------------------------
        dest = (
            attrs.get("agent.destination")
            or attrs.get("a2a.destination_agent")
            or attrs.get("destination.agent.name")
        )
        if dest:
            result.messages.append(
                models.InterAgentMessage(
                    trace_id=raw["trace_id"],
                    span_id=raw["span_id"],
                    source_agent=str(
                        attrs.get("agent.source", attrs.get("a2a.source_agent", agent))
                    ),
                    destination_agent=str(dest),
                    message_type=str(attrs.get("message.type", attrs.get("a2a.message_type", ""))),
                    transport=str(attrs.get("transport", attrs.get("network.transport", ""))),
                    network_peer=str(attrs.get("network.peer.address", "")),
                    tls_observed=_detect_tls(attrs),
                    mtls_observed=_truthy(attrs.get("tls.client.certificate"))
                    or _truthy(attrs.get("mtls.enabled")),
                    timestamp=raw["start_time"],
                )
            )

        # ---- Memory / RAG operation -----------------------------------------
        mem_op = attrs.get("memory.operation")
        rag_query = attrs.get("rag.query")
        if mem_op or rag_query or attrs.get("rag.source"):
            result.memory_ops.append(
                models.MemoryOperation(
                    trace_id=raw["trace_id"],
                    span_id=raw["span_id"],
                    agent_name=agent,
                    operation=str(mem_op or ("read" if rag_query else "")),
                    source=str(
                        attrs.get("rag.source")
                        or attrs.get("data.source.name")
                        or attrs.get("memory.source", "")
                    ),
                    source_trust=str(
                        attrs.get("source.trust")
                        or attrs.get("data.source.trust", "trusted")
                    ),
                    sanitized=_truthy(
                        attrs.get("sanitization.applied", attrs.get("content.sanitized"))
                    ),
                    rag_query=redaction.summarize(rag_query),
                    timestamp=raw["start_time"],
                )
            )

    return result


# --------------------------------------------------------------------------- #
# Public entry points                                                          #
# --------------------------------------------------------------------------- #
def load_trace_file(path: Path) -> NormalizedTrace:
    """Read + normalize a trace file from disk."""
    path = Path(path)
    try:
        with path.open("r", encoding="utf-8") as handle:
            doc = json.load(handle)
    except FileNotFoundError as exc:
        raise TraceIngestError(f"Trace file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise TraceIngestError(f"Invalid JSON in {path}: {exc}") from exc
    return normalize_document(doc)


def persist(trace: NormalizedTrace, session: Session, *, replace: bool = True) -> dict[str, int]:
    """Persist normalized trace objects, optionally clearing previous runtime data."""
    from sqlmodel import delete

    if replace:
        for model in (
            models.RuntimeSpan,
            models.RuntimeToolCall,
            models.InterAgentMessage,
            models.MemoryOperation,
        ):
            session.exec(delete(model))

    for collection in (trace.spans, trace.tool_calls, trace.messages, trace.memory_ops):
        for obj in collection:
            session.add(obj)
    session.commit()
    return {
        "RuntimeSpan": len(trace.spans),
        "RuntimeToolCall": len(trace.tool_calls),
        "InterAgentMessage": len(trace.messages),
        "MemoryOperation": len(trace.memory_ops),
    }


def ingest_file(path: Path, session: Session, *, replace: bool = True) -> dict[str, int]:
    """Load, normalize and persist a trace file in one call."""
    trace = load_trace_file(path)
    return persist(trace, session, replace=replace)
