"""SQLModel database models.

These tables hold the *inventory* (agents, tools, permissions, data sources, approval
policies), the *runtime evidence* normalized from OTLP traces (spans, tool calls,
inter-agent messages), and the *assessment output* (findings, assessment runs).

Complex attributes (lists / dicts) are persisted as JSON columns so the schema stays
flexible and easy to extend toward real connectors (Copilot Studio, Bedrock, MCP, ...).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Column, Text
from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    """Timezone-aware UTC now (avoids deprecated ``datetime.utcnow``)."""
    return datetime.now(UTC)


# --------------------------------------------------------------------------- #
# Inventory                                                                    #
# --------------------------------------------------------------------------- #
class Agent(SQLModel, table=True):
    """An Agentic AI agent asset."""

    id: int | None = Field(default=None, primary_key=True)
    agent_id: str = Field(index=True, description="Stable external identifier")
    name: str = ""
    description: str = ""
    owner: str = ""
    environment: str = "unknown"  # dev / staging / prod / internal
    platform: str = "unknown"  # copilot_studio / bedrock / dify / custom ...
    model_provider: str = ""
    model_name: str = ""
    public_exposure: str = "internal"  # internal / restricted / wide / public
    trust_level: str = "medium"  # low / medium / high
    allowed_tools: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    connected_data_sources: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    connected_mcp_servers: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    tags: list[str] = Field(default_factory=list, sa_column=Column(JSON))


class User(SQLModel, table=True):
    """A human principal interacting with agents."""

    id: int | None = Field(default=None, primary_key=True)
    user_id: str = Field(index=True)
    display_name: str = ""
    email: str = ""
    department: str = ""
    role: str = ""
    groups: list[str] = Field(default_factory=list, sa_column=Column(JSON))


class Tool(SQLModel, table=True):
    """A tool an agent can invoke."""

    id: int | None = Field(default=None, primary_key=True)
    tool_id: str = Field(index=True)
    name: str = ""
    description: str = ""
    category: str = "read_only"
    risk_level: str = "low"  # low / medium / high / critical
    dangerous_capabilities: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    requires_approval: bool = False
    allowed_agents: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    allowed_scopes: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    connector_name: str = ""
    mcp_server: str = ""
    sandbox_required: bool = False


class Permission(SQLModel, table=True):
    """A grant of a tool to a principal (agent / user / role)."""

    id: int | None = Field(default=None, primary_key=True)
    permission_id: str = Field(default="", index=True)
    principal_type: str = "agent"  # agent / user / role
    principal_id: str = ""
    tool_id: str = ""
    scope: str = ""
    role: str = ""
    permission_level: str = "read"  # read / write / admin
    source: str = "config"
    expires_at: str | None = None


class DataSource(SQLModel, table=True):
    """A RAG / memory / database / file data source."""

    id: int | None = Field(default=None, primary_key=True)
    data_source_id: str = Field(default="", index=True)
    name: str = ""
    type: str = "database"  # database / vector_store / file / web / memory ...
    classification: str = "internal"  # public / internal / confidential / restricted
    contains_pii: bool = False
    contains_confidential: bool = False
    owner: str = ""
    connected_agents: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    access_scope: str = ""
    trust: str = "trusted"  # trusted / untrusted


class ApprovalPolicy(SQLModel, table=True):
    """Human-in-the-loop approval requirement for a tool."""

    id: int | None = Field(default=None, primary_key=True)
    policy_id: str = Field(default="", index=True)
    tool_id: str = ""
    required: bool = True
    approver_role: str = ""
    condition: str = ""
    timeout_seconds: int = 0
    bypass_allowed: bool = False


# --------------------------------------------------------------------------- #
# Runtime evidence                                                             #
# --------------------------------------------------------------------------- #
class RuntimeSpan(SQLModel, table=True):
    """A normalized OTLP span."""

    id: int | None = Field(default=None, primary_key=True)
    trace_id: str = Field(index=True)
    span_id: str = Field(index=True)
    parent_span_id: str = ""
    name: str = ""
    kind: str = ""
    start_time: str = ""
    end_time: str = ""
    duration_ms: float = 0.0
    status: str = "UNSET"
    attributes: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    events: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))


class RuntimeToolCall(SQLModel, table=True):
    """A tool invocation normalized from a span."""

    id: int | None = Field(default=None, primary_key=True)
    trace_id: str = Field(index=True)
    span_id: str = Field(index=True)
    sequence_index: int = 0
    agent_name: str = ""
    tool_name: str = ""
    arguments: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    output_summary: str = Field(default="", sa_column=Column(Text))
    status: str = "UNSET"
    approval_observed: bool = False
    approval_status: str = ""
    credential_scope: str = ""
    network_peer: str = ""
    network_port: str = ""
    tls_observed: bool = False
    mcp_server: str = ""
    timestamp: str = ""


class InterAgentMessage(SQLModel, table=True):
    """A message passed from one agent to another."""

    id: int | None = Field(default=None, primary_key=True)
    trace_id: str = Field(index=True)
    span_id: str = ""
    source_agent: str = ""
    destination_agent: str = ""
    message_type: str = ""
    transport: str = ""
    network_peer: str = ""
    tls_observed: bool = False
    mtls_observed: bool = False
    timestamp: str = ""


class MemoryOperation(SQLModel, table=True):
    """A memory / RAG read or write observed in a trace."""

    id: int | None = Field(default=None, primary_key=True)
    trace_id: str = Field(index=True)
    span_id: str = ""
    agent_name: str = ""
    operation: str = ""  # read / write
    source: str = ""
    source_trust: str = "trusted"  # trusted / untrusted
    sanitized: bool = False
    rag_query: str = Field(default="", sa_column=Column(Text))
    timestamp: str = ""


# --------------------------------------------------------------------------- #
# Assessment output                                                            #
# --------------------------------------------------------------------------- #
class Finding(SQLModel, table=True):
    """A risk finding produced by the rule engine."""

    id: int | None = Field(default=None, primary_key=True)
    finding_id: str = Field(default="", index=True)
    rule_id: str = ""
    title: str = ""
    description: str = Field(default="", sa_column=Column(Text))
    owasp_category: str = ""
    severity: str = "low"
    likelihood: int = 1
    impact: int = 1
    confidence: int = 1
    risk_score: int = 0
    affected_agent: str = ""
    affected_tool: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    remediation: str = Field(default="", sa_column=Column(Text))
    references: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    assessment_run_id: int = 0
    created_at: str = Field(default_factory=lambda: utcnow().isoformat())


class AssessmentRun(SQLModel, table=True):
    """A single assessment execution summary."""

    id: int | None = Field(default=None, primary_key=True)
    name: str = ""
    created_at: str = Field(default_factory=lambda: utcnow().isoformat())
    config_sources: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    trace_sources: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    total_agents: int = 0
    total_tools: int = 0
    total_findings: int = 0
    risk_score: int = 0
    agent_scores: dict[str, int] = Field(default_factory=dict, sa_column=Column(JSON))
    owasp_counts: dict[str, int] = Field(default_factory=dict, sa_column=Column(JSON))


ALL_TABLE_MODELS = [
    Agent,
    User,
    Tool,
    Permission,
    DataSource,
    ApprovalPolicy,
    RuntimeSpan,
    RuntimeToolCall,
    InterAgentMessage,
    MemoryOperation,
    Finding,
    AssessmentRun,
]
