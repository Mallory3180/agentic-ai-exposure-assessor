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
from .live import (
    INVENTORY_CONNECTORS,
    AzureOpenAIInventoryConnector,
    BedrockInventoryConnector,
    ConnectorError,
    ConnectorNotConfigured,
    DifyInventoryConnector,
    GenericHttpInventoryConnector,
    LiveInventoryConnector,
    McpInventoryConnector,
    build_inventory_connector,
)
from .otlp_file_connector import OtlpFileConnector

CONFIG_CONNECTORS = {
    "fixture": FixtureConnector,
    "copilot_studio": CopilotStudioConnector,
    "chatgpt_enterprise": ChatGptEnterpriseConnector,
}

# Live inventory connectors keyed by target platform.
LIVE_INVENTORY_CONNECTORS = INVENTORY_CONNECTORS

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
    "LiveInventoryConnector",
    "GenericHttpInventoryConnector",
    "DifyInventoryConnector",
    "AzureOpenAIInventoryConnector",
    "BedrockInventoryConnector",
    "McpInventoryConnector",
    "ConnectorError",
    "ConnectorNotConfigured",
    "build_inventory_connector",
    "CONFIG_CONNECTORS",
    "LIVE_INVENTORY_CONNECTORS",
    "TRACE_CONNECTORS",
]
