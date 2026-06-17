"""Stub connector for ChatGPT Enterprise (future extension)."""

from __future__ import annotations

from .base import StubConnector


class ChatGptEnterpriseConnector(StubConnector):
    name = "chatgpt_enterprise"
    docs_url = "https://help.openai.com/en/articles/8265053-chatgpt-enterprise"
