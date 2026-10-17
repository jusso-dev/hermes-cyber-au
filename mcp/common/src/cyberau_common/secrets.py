"""Environment lookup and redaction. Secret values are never logged."""

from __future__ import annotations

import os
import re

_SECRET_HEADERS = {
    "authorization",
    "auth-key",
    "x-otx-api-key",
    "x-api-key",
    "api-key",
    "apikey",
    "x-rftoken",
}

_QUERY_RE = re.compile(r"(?i)([?&](?:api[_-]?key|token|auth|key|access_token)=)[^&\s]+")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+\S+")
_HEADER_RE = re.compile(
    r"(?i)\b(authorization|auth-key|x-otx-api-key|x-api-key|x-rftoken|api[_-]?key)\s*[:=]\s*\S+"
)


def lookup(name: str) -> str | None:
    """Return an environment value, or None when it is missing or blank."""
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return None
    return value


def redact(text: str) -> str:
    """Replace secret-shaped header and query values with a fixed marker."""
    text = _QUERY_RE.sub(r"\1[REDACTED]", text)
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    text = _HEADER_RE.sub(r"\1: [REDACTED]", text)
    return text


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in _SECRET_HEADERS:
            cleaned[key] = "[REDACTED]"
        else:
            cleaned[key] = value
    return cleaned


class RedactFilter:
    """Logging filter that rewrites the rendered message."""

    def filter(self, record) -> bool:
        rendered = redact(record.getMessage())
        record.msg = rendered
        record.args = ()
        return True
