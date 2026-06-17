"""Rule engine primitives: assessment context, dangerous-argument detection, base rule.

A :class:`Rule` is any callable taking an :class:`AssessmentContext` and returning a list
of :class:`~agentic_ai_exposure_assessor.schemas.FindingDraft`. Rules are pure functions of
the context (inventory + runtime evidence) so they are easy to unit test in isolation.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .. import models, redaction
from ..schemas import FindingDraft

# --------------------------------------------------------------------------- #
# Dangerous argument detection (shared by several rules)                       #
# --------------------------------------------------------------------------- #
_URL_RE = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
_WIN_PATH_RE = re.compile(r"[A-Za-z]:[\\/][^\s'\"]+")
_POSIX_SENSITIVE_PATH_RE = re.compile(r"(?:^|\s)(/etc/|/var/|/root/|/usr/bin/)[^\s'\"]*")
_SQL_WRITE_RE = re.compile(r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|MERGE)\b", re.IGNORECASE)
_SHELL_TOKEN_RE = re.compile(
    r"(?:^|\s)(rm|del|curl|wget|powershell|bash|sh|cmd|nc|netcat|chmod|sudo|scp)\b"
    r"|[;&|`]|\$\(",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")


@dataclass
class DangerSignal:
    kind: str
    detail: str


def _iter_strings(value: Any, key: str = "") -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for k, v in value.items():
            out.extend(_iter_strings(v, str(k)))
    elif isinstance(value, list):
        for item in value:
            out.extend(_iter_strings(item, key))
    elif isinstance(value, str):
        out.append((key, value))
    return out


def scan_dangerous_arguments(
    arguments: dict[str, Any], *, internal_domains: set[str] | None = None
) -> list[DangerSignal]:
    """Return a list of dangerous-argument signals found in tool arguments."""
    internal_domains = internal_domains or set()
    signals: list[DangerSignal] = []
    for key, text in _iter_strings(arguments):
        sample = redaction.summarize(text, limit=120)
        if _SHELL_TOKEN_RE.search(text):
            signals.append(DangerSignal("shell_command", f"{key}={sample}"))
        if _URL_RE.search(text):
            signals.append(DangerSignal("external_url", f"{key}={sample}"))
        if _WIN_PATH_RE.search(text) or _POSIX_SENSITIVE_PATH_RE.search(text):
            signals.append(DangerSignal("file_path", f"{key}={sample}"))
        if redaction.looks_secret(text):
            signals.append(DangerSignal("credential_like", f"{key}=***"))
        if _SQL_WRITE_RE.search(text):
            signals.append(DangerSignal("sql_write", f"{key}={sample}"))
        for match in _EMAIL_RE.findall(text):
            domain = match.split("@", 1)[1].lower()
            if domain not in internal_domains:
                signals.append(DangerSignal("email_external_recipient", f"{key}={match}"))
    # De-duplicate while keeping order.
    seen: set[tuple[str, str]] = set()
    unique: list[DangerSignal] = []
    for sig in signals:
        token = (sig.kind, sig.detail)
        if token not in seen:
            seen.add(token)
            unique.append(sig)
    return unique


# --------------------------------------------------------------------------- #
# Assessment context                                                          #
# --------------------------------------------------------------------------- #
@dataclass
class AssessmentContext:
    """Everything a rule needs: inventory plus runtime evidence."""

    agents: list[models.Agent] = field(default_factory=list)
    users: list[models.User] = field(default_factory=list)
    tools: list[models.Tool] = field(default_factory=list)
    permissions: list[models.Permission] = field(default_factory=list)
    data_sources: list[models.DataSource] = field(default_factory=list)
    approval_policies: list[models.ApprovalPolicy] = field(default_factory=list)
    spans: list[models.RuntimeSpan] = field(default_factory=list)
    tool_calls: list[models.RuntimeToolCall] = field(default_factory=list)
    messages: list[models.InterAgentMessage] = field(default_factory=list)
    memory_ops: list[models.MemoryOperation] = field(default_factory=list)
    internal_domains: set[str] = field(default_factory=set)

    # Tunable thresholds (ASI08).
    max_tool_calls_per_trace: int = 12
    max_tool_retries: int = 3

    # ---- lookups -----------------------------------------------------------
    def agent_for(self, name: str) -> models.Agent | None:
        if not name:
            return None
        for agent in self.agents:
            if name in (agent.agent_id, agent.name):
                return agent
        return None

    def tool_for(self, name: str) -> models.Tool | None:
        if not name:
            return None
        for tool in self.tools:
            if name in (tool.tool_id, tool.name):
                return tool
        return None

    def data_source_for(self, name: str) -> models.DataSource | None:
        if not name:
            return None
        for ds in self.data_sources:
            if name in (ds.data_source_id, ds.name):
                return ds
        return None

    def approval_policy_for(self, tool: models.Tool) -> models.ApprovalPolicy | None:
        names = {tool.tool_id, tool.name}
        for policy in self.approval_policies:
            if policy.tool_id in names:
                return policy
        return None

    def permissions_for_agent(self, agent: models.Agent) -> list[models.Permission]:
        names = {agent.agent_id, agent.name}
        return [
            p
            for p in self.permissions
            if p.principal_type == "agent" and p.principal_id in names
        ]


# A rule is a callable returning FindingDrafts.
Rule = Callable[[AssessmentContext], list[FindingDraft]]
