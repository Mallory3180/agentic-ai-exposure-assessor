"""Mermaid graph generation for runtime traces.

Builds per-trace ``graph TD`` / ``sequenceDiagram`` Mermaid sources from normalized tool
calls and inter-agent messages. Node identifiers are sanitized so that Windows paths or
tool names with special characters do not break the diagram.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from . import models

_SAFE = re.compile(r"[^A-Za-z0-9_]")


def _node_id(prefix: str, value: str) -> str:
    cleaned = _SAFE.sub("_", value or "unknown")
    return f"{prefix}_{cleaned}"[:60]


def _label(value: str) -> str:
    """Escape a label for inclusion inside Mermaid ``[...]`` brackets."""
    return (value or "?").replace('"', "'").replace("[", "(").replace("]", ")")


def tool_sequence_mermaid(tool_calls: list[models.RuntimeToolCall]) -> str:
    """A top-down flow graph of a single trace's tool-call sequence."""
    if not tool_calls:
        return "graph TD\n    empty[No tool calls in trace]"

    ordered = sorted(tool_calls, key=lambda c: c.sequence_index)
    lines = ["graph TD"]
    agents_seen: set[str] = set()

    prev_step: str | None = None
    for call in ordered:
        agent_node = _node_id("agent", call.agent_name)
        if call.agent_name not in agents_seen:
            lines.append(f'    {agent_node}(["Agent: {_label(call.agent_name)}"])')
            agents_seen.add(call.agent_name)

        step_node = _node_id(f"call{call.sequence_index}", call.tool_name)
        flags = []
        if not call.approval_observed and call.approval_status:
            flags.append(f"approval={_label(call.approval_status)}")
        if call.tool_name:
            label = f"{call.sequence_index + 1}. {_label(call.tool_name)}"
        else:
            label = f"{call.sequence_index + 1}. (tool)"
        if flags:
            label += " " + " ".join(flags)
        lines.append(f'    {step_node}["{label}"]')
        lines.append(f"    {agent_node} --> {step_node}")
        if prev_step:
            lines.append(f"    {prev_step} -.-> {step_node}")
        prev_step = step_node

    return "\n".join(lines)


def inter_agent_mermaid(messages: Iterable[models.InterAgentMessage]) -> str:
    """A sequence diagram of agent-to-agent messages, flagging missing TLS."""
    messages = list(messages)
    if not messages:
        return "sequenceDiagram\n    note over none: No inter-agent messages"

    lines = ["sequenceDiagram"]
    for msg in messages:
        src = _SAFE.sub("_", msg.source_agent or "unknown")
        dst = _SAFE.sub("_", msg.destination_agent or "unknown")
        tls = "TLS" if msg.tls_observed else "NO-TLS"
        label = f"{_label(msg.message_type or 'message')} [{tls}]"
        lines.append(f"    {src}->>{dst}: {label}")
    return "\n".join(lines)


def trace_graphs(
    tool_calls: list[models.RuntimeToolCall],
    messages: list[models.InterAgentMessage],
) -> dict[str, dict[str, str]]:
    """Return ``{trace_id: {"tool_sequence": ..., "inter_agent": ...}}``."""
    by_trace: dict[str, dict[str, str]] = {}
    trace_ids = {c.trace_id for c in tool_calls} | {m.trace_id for m in messages}
    for trace_id in sorted(trace_ids):
        calls = [c for c in tool_calls if c.trace_id == trace_id]
        msgs = [m for m in messages if m.trace_id == trace_id]
        by_trace[trace_id] = {
            "tool_sequence": tool_sequence_mermaid(calls),
            "inter_agent": inter_agent_mermaid(msgs),
        }
    return by_trace
