"""Load inventory YAML fixtures into validated objects and persist them.

Each fixture file maps to a Pydantic schema for validation and a SQLModel table for
persistence. Parsing is tolerant about the top-level container: a file may be either a
bare list of records, or a mapping with a single top-level key (e.g. ``agents:``) whose
value is the list. Invalid YAML or schema violations raise :class:`ConfigError` with a
readable message that names the offending file.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ValidationError
from sqlmodel import Session, delete

from . import models, schemas


class ConfigError(Exception):
    """Raised when a fixture file cannot be read or validated."""


# record-type -> (schema, model). Single source for both file and live (connector) loading.
_RECORD_MAP: dict[str, tuple[type[BaseModel], type]] = {
    "agents": (schemas.AgentIn, models.Agent),
    "tools": (schemas.ToolIn, models.Tool),
    "permissions": (schemas.PermissionIn, models.Permission),
    "data_sources": (schemas.DataSourceIn, models.DataSource),
    "approval_policies": (schemas.ApprovalPolicyIn, models.ApprovalPolicy),
    "users": (schemas.UserIn, models.User),
}

# (filename, top-level-key, record-type)
_FILE_MAP: list[tuple[str, str, str]] = [
    ("agent_inventory.yml", "agents", "agents"),
    ("tool_registry.yml", "tools", "tools"),
    ("permissions.yml", "permissions", "permissions"),
    ("data_sources.yml", "data_sources", "data_sources"),
    ("approval_policies.yml", "approval_policies", "approval_policies"),
    ("users.yml", "users", "users"),
]


def _read_yaml(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle)
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc


def _extract_records(data: Any, top_key: str, path: Path) -> list[dict[str, Any]]:
    """Pull the list of records out of a loaded YAML document."""
    if data is None:
        return []
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        if top_key in data:
            records = data[top_key]
        elif len(data) == 1:
            records = next(iter(data.values()))
        else:
            raise ConfigError(
                f"{path}: expected a list or a top-level '{top_key}:' key, "
                f"got keys {list(data)}"
            )
    else:
        raise ConfigError(f"{path}: unexpected top-level type {type(data).__name__}")
    if records is None:
        return []
    if not isinstance(records, list):
        raise ConfigError(f"{path}: '{top_key}' must be a list, got {type(records).__name__}")
    return records


def _validate(
    records: Iterable[dict[str, Any]], schema: type[BaseModel], path: Path
) -> list[BaseModel]:
    validated = []
    for index, raw in enumerate(records):
        if not isinstance(raw, dict):
            raise ConfigError(f"{path}: record #{index} is not a mapping")
        try:
            validated.append(schema.model_validate(raw))
        except ValidationError as exc:
            raise ConfigError(f"{path}: record #{index} failed validation:\n{exc}") from exc
    return validated


def _to_model(validated: BaseModel, model: type) -> Any:
    """Convert a validated schema object into a table row, dropping aliases."""
    return model(**validated.model_dump())


def load_directory(fixtures_dir: Path, session: Session, *, replace: bool = True) -> dict[str, int]:
    """Load every known fixture file from ``fixtures_dir`` into the database.

    Returns a mapping of model name -> number of rows inserted. Missing optional files are
    skipped silently; only present files are processed.
    """
    fixtures_dir = Path(fixtures_dir)
    if not fixtures_dir.exists():
        raise ConfigError(f"Fixtures directory does not exist: {fixtures_dir}")

    records_by_type: dict[str, list[dict[str, Any]]] = {}
    for filename, top_key, record_type in _FILE_MAP:
        path = fixtures_dir / filename
        if not path.exists():
            continue
        data = _read_yaml(path)
        records_by_type[record_type] = _extract_records(data, top_key, path)

    return load_records(records_by_type, session, replace=replace, source=str(fixtures_dir))


def load_records(
    records_by_type: dict[str, list[dict[str, Any]]],
    session: Session,
    *,
    replace: bool = True,
    source: str = "live",
) -> dict[str, int]:
    """Validate and persist already-parsed inventory records (from files or a live connector).

    ``records_by_type`` maps a record type (``agents``/``tools``/...) to a list of raw dicts.
    Unknown record types raise :class:`ConfigError`. Returns a mapping of model name -> count.
    """
    counts: dict[str, int] = {}
    for record_type, records in records_by_type.items():
        if record_type not in _RECORD_MAP:
            raise ConfigError(
                f"{source}: unknown record type '{record_type}' "
                f"(expected one of {sorted(_RECORD_MAP)})"
            )
        schema, model = _RECORD_MAP[record_type]
        validated = _validate(records or [], schema, Path(source))

        if replace:
            session.exec(delete(model))

        inserted = 0
        for item in validated:
            session.add(_to_model(item, model))
            inserted += 1
        counts[model.__name__] = inserted

    session.commit()
    return counts
