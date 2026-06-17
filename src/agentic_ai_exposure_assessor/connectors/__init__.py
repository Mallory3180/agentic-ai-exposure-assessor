"""Connector registry.

Config connectors hydrate inventory; trace connectors hydrate runtime evidence. Cloud
connectors are stubs documenting the extension points (Copilot Studio, ChatGPT Enterprise,
and — by analogy — Dify, Bedrock Agents, MCP servers).
"""

from __future__ import annotations

from .base import ConfigConnector, StubConnector, TraceConnector
from .chatgpt_enterprise_stub import ChatGptEnterpriseConnector
from .copilot_stub import CopilotStudioConnector
from .fixture_connector import FixtureConnector
from .otlp_file_connector import OtlpFileConnector

CONFIG_CONNECTORS = {
    "fixture": FixtureConnector,
    "copilot_studio": CopilotStudioConnector,
    "chatgpt_enterprise": ChatGptEnterpriseConnector,
}

TRACE_CONNECTORS = {
    "otlp_file": OtlpFileConnector,
}

__all__ = [
    "ConfigConnector",
    "TraceConnector",
    "StubConnector",
    "FixtureConnector",
    "OtlpFileConnector",
    "CopilotStudioConnector",
    "ChatGptEnterpriseConnector",
    "CONFIG_CONNECTORS",
    "TRACE_CONNECTORS",
]
