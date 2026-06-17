"""Pydantic v2 schemas for validated input parsing and internal DTOs.

These describe the *shape of the YAML/JSON fixtures* and the data transfer objects passed
between the rule engine, scoring and reporting layers. They are deliberately separate from
the SQLModel tables so that file parsing failures produce clear validation errors before
anything touches the database.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _Base(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)


# --------------------------------------------------------------------------- #
# Inventory input schemas (mirror the fixture YAML files)                      #
# --------------------------------------------------------------------------- #
class AgentIn(_Base):
    agent_id: str = Field(alias="id")
    name: str = ""
    description: str = ""
    owner: str = ""
    environment: str = "unknown"
    platform: str = "unknown"
    model_provider: str = ""
    model_name: str = ""
    public_exposure: str = "internal"
    trust_level: str = "medium"
    allowed_tools: list[str] = Field(default_factory=list)
    connected_data_sources: list[str] = Field(default_factory=list)
    connected_mcp_servers: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class ToolIn(_Base):
    tool_id: str = Field(alias="id")
    name: str = ""
    description: str = ""
    category: str = "read_only"
    risk_level: str = "low"
    dangerous_capabilities: list[str] = Field(default_factory=list)
    requires_approval: bool = False
    allowed_agents: list[str] = Field(default_factory=list)
    allowed_scopes: list[str] = Field(default_factory=list)
    connector_name: str = ""
    mcp_server: str = ""
    sandbox_required: bool = False


class PermissionIn(_Base):
    permission_id: str = Field(default="", alias="id")
    principal_type: str = "agent"
    principal_id: str = ""
    tool_id: str = ""
    scope: str = ""
    role: str = ""
    permission_level: str = "read"
    source: str = "config"
    expires_at: str | None = None


class DataSourceIn(_Base):
    data_source_id: str = Field(default="", alias="id")
    name: str = ""
    type: str = "database"
    classification: str = "internal"
    contains_pii: bool = False
    contains_confidential: bool = False
    owner: str = ""
    connected_agents: list[str] = Field(default_factory=list)
    access_scope: str = ""
    trust: str = "trusted"


class ApprovalPolicyIn(_Base):
    policy_id: str = Field(default="", alias="id")
    tool_id: str = ""
    required: bool = True
    approver_role: str = ""
    condition: str = ""
    timeout_seconds: int = 0
    bypass_allowed: bool = False


class UserIn(_Base):
    user_id: str = Field(alias="id")
    display_name: str = ""
    email: str = ""
    department: str = ""
    role: str = ""
    groups: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Rule engine DTOs                                                             #
# --------------------------------------------------------------------------- #
class FindingDraft(_Base):
    """A finding produced by a rule, before scoring / persistence."""

    rule_id: str
    title: str
    description: str = ""
    owasp_category: str = ""
    likelihood: int = 1
    impact: int = 1
    confidence: int = 3
    affected_agent: str = ""
    affected_tool: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)


class ReportSummary(_Base):
    """Lightweight summary used by report/UI layers."""

    run_name: str = ""
    created_at: str = ""
    total_agents: int = 0
    total_tools: int = 0
    total_findings: int = 0
    risk_score: int = 0
    agent_scores: dict[str, int] = Field(default_factory=dict)
    owasp_counts: dict[str, int] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)
