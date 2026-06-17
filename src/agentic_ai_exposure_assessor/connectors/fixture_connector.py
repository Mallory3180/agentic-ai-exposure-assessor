"""Fixture-based config connector: reads inventory YAML from a directory."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .base import ConfigConnector

_FILES = {
    "agents": ("agent_inventory.yml", "agents"),
    "tools": ("tool_registry.yml", "tools"),
    "permissions": ("permissions.yml", "permissions"),
    "data_sources": ("data_sources.yml", "data_sources"),
    "approval_policies": ("approval_policies.yml", "approval_policies"),
    "users": ("users.yml", "users"),
}


class FixtureConnector(ConfigConnector):
    name = "fixture"

    def __init__(self, fixtures_dir: Path) -> None:
        self.fixtures_dir = Path(fixtures_dir)

    def load(self) -> dict[str, list[dict[str, Any]]]:
        result: dict[str, list[dict[str, Any]]] = {}
        for record_type, (filename, top_key) in _FILES.items():
            path = self.fixtures_dir / filename
            if not path.exists():
                result[record_type] = []
                continue
            with path.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
            if isinstance(data, dict):
                records = data.get(top_key, [])
            elif isinstance(data, list):
                records = data
            else:
                records = []
            result[record_type] = list(records or [])
        return result
