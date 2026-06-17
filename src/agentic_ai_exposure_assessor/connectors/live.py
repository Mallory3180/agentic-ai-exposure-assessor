"""Live inventory connectors.

These pull *inventory* (agents / tools / permissions / data sources / approval policies)
from a running platform, as opposed to reading static fixture YAML. Each connector returns
the same ``{record_type: [records...]}`` mapping the fixture connector produces, so the rest
of the pipeline (validation, persistence, rules) is unchanged.

Design rules:

* **No secrets in config files.** A target declares ``token_env`` (the *name* of an
  environment variable); the connector reads the credential from the environment at runtime.
* **Read-only.** Connectors only enumerate/read configuration. They never mutate the target
  and never send prompts to it.

The ``generic_http`` connector is fully implemented (and unit tested). The cloud connectors
(Dify / Azure OpenAI / Bedrock / MCP) are documented extension points: they declare the
exact connection info they need and raise :class:`ConnectorNotConfigured` until implemented
for a concrete tenant, so the wiring is obvious without guessing vendor APIs/credentials.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

from ..schemas import TargetIn
from .base import ConfigConnector

_KNOWN_RECORD_TYPES = {
    "agents",
    "tools",
    "permissions",
    "data_sources",
    "approval_policies",
    "users",
}


class ConnectorError(Exception):
    """Raised when a live connector cannot retrieve inventory."""


class ConnectorNotConfigured(ConnectorError):
    """Raised by a cloud connector that needs tenant-specific implementation/credentials."""


def _resolve_token(inventory: dict[str, Any]) -> str | None:
    """Read a credential from the environment variable named by ``token_env``."""
    env_name = inventory.get("token_env")
    if not env_name:
        return None
    token = os.environ.get(str(env_name))
    if not token:
        raise ConnectorError(
            f"Environment variable '{env_name}' is not set (required for this target)."
        )
    return token


class LiveInventoryConnector(ConfigConnector):
    """Base class for connectors that read inventory from a live platform."""

    def __init__(self, target: TargetIn) -> None:
        self.target = target
        self.inventory_cfg = target.inventory or {}


class GenericHttpInventoryConnector(LiveInventoryConnector):
    """Pull inventory from an HTTP(S) JSON endpoint.

    Expected target config::

        inventory:
          base_url: https://example.internal/agentic-inventory
          token_env: MY_INVENTORY_TOKEN     # optional; sent as Bearer token
          verify_tls: true                  # optional, default true

    The endpoint must return JSON shaped like the fixtures, e.g.
    ``{"agents": [...], "tools": [...], "permissions": [...]}``.
    """

    name = "generic_http"

    def _fetch(self, url: str, headers: dict[str, str]) -> Any:
        request = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 (https URL)
            charset = response.headers.get_content_charset() or "utf-8"
            return json.loads(response.read().decode(charset))

    def load(self) -> dict[str, list[dict[str, Any]]]:
        base_url = self.inventory_cfg.get("base_url")
        if not base_url:
            raise ConnectorError(
                f"Target '{self.target.target_id}': inventory.base_url is required"
            )
        headers = {"Accept": "application/json"}
        token = _resolve_token(self.inventory_cfg)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            payload = self._fetch(str(base_url), headers)
        except ConnectorError:
            raise
        except Exception as exc:  # network / decode errors
            raise ConnectorError(
                f"Target '{self.target.target_id}': failed to fetch inventory from "
                f"{base_url}: {exc}"
            ) from exc

        if isinstance(payload, dict) and "inventory" in payload:
            payload = payload["inventory"]
        if not isinstance(payload, dict):
            raise ConnectorError(
                f"Target '{self.target.target_id}': inventory endpoint must return a JSON object"
            )
        return {
            key: list(value or [])
            for key, value in payload.items()
            if key in _KNOWN_RECORD_TYPES
        }


class _CloudStubConnector(LiveInventoryConnector):
    """Documented, not-yet-implemented cloud inventory connector."""

    required_config: str = ""
    docs_url: str = ""

    def load(self) -> dict[str, list[dict[str, Any]]]:
        raise ConnectorNotConfigured(
            f"The '{self.name}' inventory connector is not implemented in this MVP.\n"
            f"Required target.inventory config: {self.required_config}\n"
            f"Reference: {self.docs_url}\n"
            f"Implement {type(self).__name__}.load() to enumerate assets for your tenant."
        )


class DifyInventoryConnector(_CloudStubConnector):
    name = "dify"
    required_config = (
        "base_url (e.g. https://api.dify.ai/v1 or self-hosted), token_env "
        "(Dify API key / console token); enumerate apps -> map each app/agent to an Agent, "
        "its enabled tools to Tool, and knowledge bases to DataSource."
    )
    docs_url = "https://docs.dify.ai/"


class AzureOpenAIInventoryConnector(_CloudStubConnector):
    name = "azure_openai"
    required_config = (
        "endpoint (https://<resource>.openai.azure.com), token_env (API key or AAD token), "
        "api_version; enumerate deployments and Assistants/agents, their tools/functions, "
        "and data sources (e.g. On Your Data / AI Search) -> Agent/Tool/DataSource."
    )
    docs_url = "https://learn.microsoft.com/azure/ai-services/openai/"


class BedrockInventoryConnector(_CloudStubConnector):
    name = "bedrock"
    required_config = (
        "region, AWS credentials via standard env (AWS_ACCESS_KEY_ID/SECRET/SESSION or role); "
        "use bedrock-agent ListAgents/ListAgentActionGroups (incl. MCP/Gateway targets) and "
        "knowledge bases -> Agent/Tool/DataSource. Read-only IAM (bedrock:List*/Get*)."
    )
    docs_url = "https://docs.aws.amazon.com/bedrock/latest/userguide/agents.html"


class McpInventoryConnector(_CloudStubConnector):
    name = "mcp"
    required_config = (
        "server_url (HTTP/SSE) or command (stdio), optional token_env; call MCP 'tools/list' "
        "to enumerate tools (-> Tool with mcp_server set) and 'resources/list' for data "
        "sources. One MCP server typically maps to many Tool records."
    )
    docs_url = "https://modelcontextprotocol.io/"


INVENTORY_CONNECTORS: dict[str, type[LiveInventoryConnector]] = {
    "generic_http": GenericHttpInventoryConnector,
    "dify": DifyInventoryConnector,
    "azure_openai": AzureOpenAIInventoryConnector,
    "bedrock": BedrockInventoryConnector,
    "mcp": McpInventoryConnector,
}


def build_inventory_connector(target: TargetIn) -> LiveInventoryConnector:
    """Instantiate the inventory connector for a target's platform."""
    connector_cls = INVENTORY_CONNECTORS.get(target.platform)
    if connector_cls is None:
        raise ConnectorError(
            f"Target '{target.target_id}': unknown platform '{target.platform}' "
            f"(known: {sorted(INVENTORY_CONNECTORS)})"
        )
    return connector_cls(target)
