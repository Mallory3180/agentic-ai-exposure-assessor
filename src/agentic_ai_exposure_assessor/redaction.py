"""Secret redaction / privacy utilities.

The assessor must never persist or render secret-like values. This module provides
detection + masking for API keys, bearer tokens, passwords, private keys and (optionally)
email addresses, plus helpers that recursively redact dict/list structures coming from
trace attributes and tool arguments.

By design, raw prompts and raw tool outputs are *summarized* (truncated) rather than
stored verbatim — see :func:`summarize`.
"""

from __future__ import annotations

import re
from typing import Any

MASK = "***REDACTED***"

# Ordered list of (compiled pattern, replacement). Patterns are intentionally broad: this
# is a defensive tool, so over-redaction is preferable to leaking a credential.
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # PEM private keys
    (re.compile(r"-----BEGIN [^-]+ PRIVATE KEY-----.*?-----END [^-]+ PRIVATE KEY-----", re.S),
     MASK),
    # Bearer tokens
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{8,}"), f"Bearer {MASK}"),
    # AWS access key id
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), MASK),
    # Common provider key prefixes (OpenAI / GitHub / Slack / Google etc.)
    (re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9]{16,}\b"), MASK),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), MASK),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), MASK),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}\b"), MASK),
    # key=value style secrets
    (re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key)\b"
                r"\s*[:=]\s*['\"]?[A-Za-z0-9._\-/+]{6,}['\"]?"),
     r"\1=" + MASK),
]

_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

# Keys whose values should always be masked regardless of content.
_SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "access_key", "secret_key", "authorization", "auth", "private_key",
    "client_secret", "credential", "credentials",
}


def redact_text(text: str, *, mask_emails: bool = False) -> str:
    """Redact secret-like substrings (and optionally emails) from a string."""
    if not text:
        return text
    result = text
    for pattern, replacement in _SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    if mask_emails:
        result = _EMAIL_PATTERN.sub(mask_email, result)
    return result


def mask_email(value: str | re.Match[str]) -> str:
    """Mask the local part of an email, keeping the domain for context."""
    email = value.group(0) if isinstance(value, re.Match) else value
    if "@" not in email:
        return MASK
    local, _, domain = email.partition("@")
    keep = local[0] if local else ""
    return f"{keep}***@{domain}"


def looks_secret(value: str) -> bool:
    """Heuristic: does this string contain a secret-like value?"""
    if not value:
        return False
    for pattern, _ in _SECRET_PATTERNS:
        if pattern.search(value):
            return True
    return False


def redact_value(value: Any, *, key: str | None = None, mask_emails: bool = False) -> Any:
    """Recursively redact a JSON-like structure (dict / list / scalar)."""
    if isinstance(value, dict):
        return {k: redact_value(v, key=k, mask_emails=mask_emails) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v, key=key, mask_emails=mask_emails) for v in value]
    if isinstance(value, str):
        if key and key.lower() in _SENSITIVE_KEYS:
            return MASK
        return redact_text(value, mask_emails=mask_emails)
    return value


def summarize(text: str | None, *, limit: int = 280, mask_emails: bool = False) -> str:
    """Redact then truncate free-form text so raw prompts/outputs are never stored whole."""
    if not text:
        return ""
    redacted = redact_text(str(text), mask_emails=mask_emails)
    if len(redacted) <= limit:
        return redacted
    return redacted[:limit].rstrip() + " …[truncated]"
