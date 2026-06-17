"""Connector interfaces.

A *config connector* yields inventory records (agents, tools, ...). A *trace connector*
yields a normalized trace. The MVP ships a fixture-based config connector and an OTLP file
trace connector; cloud connectors are stubs that document the intended extension point.
"""

from __future__ import annotations

import abc
from pathlib import Path
from typing import Any


class ConfigConnector(abc.ABC):
    """Produces inventory data (agents/tools/permissions/...) from some source."""

    name: str = "base"

    @abc.abstractmethod
    def load(self) -> dict[str, list[dict[str, Any]]]:
        """Return a mapping of record-type -> list of raw records."""
        raise NotImplementedError


class TraceConnector(abc.ABC):
    """Produces runtime trace documents from some source."""

    name: str = "base"

    @abc.abstractmethod
    def load(self) -> Any:
        """Return a parsed trace document (OTLP-style dict or list of spans)."""
        raise NotImplementedError


class StubConnector(ConfigConnector):
    """Base for not-yet-implemented cloud connectors."""

    docs_url: str = ""

    def __init__(self, config_path: Path | None = None) -> None:
        self.config_path = config_path

    def load(self) -> dict[str, list[dict[str, Any]]]:
        raise NotImplementedError(
            f"The '{self.name}' connector is a stub in this MVP. "
            f"Implement {type(self).__name__}.load() to pull live inventory. "
            f"See: {self.docs_url or 'README — Future Extensions'}"
        )
