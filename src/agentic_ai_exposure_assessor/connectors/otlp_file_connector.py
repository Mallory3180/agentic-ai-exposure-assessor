"""OTLP file trace connector: reads an OTLP-style JSON trace from disk."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .base import TraceConnector


class OtlpFileConnector(TraceConnector):
    name = "otlp_file"

    def __init__(self, file_path: Path) -> None:
        self.file_path = Path(file_path)

    def load(self) -> Any:
        with self.file_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
