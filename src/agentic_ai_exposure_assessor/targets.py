"""Load and run live assessment *targets* (connection configs).

A targets file declares which live platforms to assess and how to reach them. Inventory is
pulled via the matching connector; runtime traces are collected separately via the OTLP
receiver (see :mod:`.app`). Secrets live in environment variables, never in the file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError
from sqlmodel import Session

from . import config_loader
from .connectors.live import ConnectorError, build_inventory_connector
from .schemas import TargetIn


class TargetsError(Exception):
    """Raised when the targets file cannot be read or validated."""


def load_targets(path: Path) -> list[TargetIn]:
    """Parse and validate a targets YAML file."""
    path = Path(path)
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except FileNotFoundError as exc:
        raise TargetsError(f"Targets file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise TargetsError(f"Invalid YAML in {path}: {exc}") from exc

    if isinstance(data, dict):
        raw_targets = data.get("targets", [])
    elif isinstance(data, list):
        raw_targets = data
    else:
        raise TargetsError(f"{path}: expected a 'targets:' list")

    targets: list[TargetIn] = []
    for index, raw in enumerate(raw_targets or []):
        try:
            targets.append(TargetIn.model_validate(raw))
        except ValidationError as exc:
            raise TargetsError(f"{path}: target #{index} failed validation:\n{exc}") from exc
    return targets


def pull_inventory(
    targets: list[TargetIn], session: Session, *, replace: bool = True
) -> dict[str, Any]:
    """Pull inventory from all enabled targets and persist it.

    Records from multiple targets are merged per record-type. ``replace`` clears existing
    inventory once before inserting the merged result.
    """
    merged: dict[str, list[dict[str, Any]]] = {}
    per_target: dict[str, str] = {}

    for target in targets:
        if not target.enabled:
            per_target[target.target_id] = "skipped (disabled)"
            continue
        connector = build_inventory_connector(target)
        try:
            records = connector.load()
        except ConnectorError as exc:
            per_target[target.target_id] = f"error: {exc}"
            continue
        for record_type, items in records.items():
            merged.setdefault(record_type, []).extend(items)
        per_target[target.target_id] = "ok (" + ", ".join(
            f"{k}:{len(v)}" for k, v in records.items()
        ) + ")"

    counts = config_loader.load_records(
        merged, session, replace=replace, source="live-targets"
    )
    return {"counts": counts, "targets": per_target}
