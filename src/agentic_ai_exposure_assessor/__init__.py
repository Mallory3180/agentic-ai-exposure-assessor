"""Agentic AI Exposure Assessor.

A defensive diagnostic / visualization tool that combines Tenable-AI-Exposure-style
asset & finding inventory with OpenTelemetry/OTLP-style runtime trace collection, and
evaluates the result against the OWASP Top 10 for Agentic Applications 2026.

This package is intentionally Docker-free and runs on a plain local Python virtual
environment (Windows + Git Bash friendly). All filesystem access uses ``pathlib.Path``.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
