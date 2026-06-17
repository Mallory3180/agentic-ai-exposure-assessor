"""Stub connector for Microsoft Copilot Studio (future extension)."""

from __future__ import annotations

from .base import StubConnector


class CopilotStudioConnector(StubConnector):
    name = "copilot_studio"
    docs_url = "https://learn.microsoft.com/microsoft-copilot-studio/"
