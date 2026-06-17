"""Framework integrations that emit OTLP traces to the assessor's receiver.

These are optional and import their (heavy) dependencies lazily, so importing this package
never requires opentelemetry / openinference to be installed.
"""

from __future__ import annotations

__all__ = ["langgraph"]
