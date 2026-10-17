"""Replace passwords, cookies, tokens and emails with a type and a short hash."""

from __future__ import annotations

import hashlib
import re

_SECRET_KEYS = {
    "password",
    "passwd",
    "pwd",
    "cookie",
    "cookies",
    "token",
    "secret",
    "api_key",
    "apikey",
    "session",
    "sessionid",
}

_PASSWORD = re.compile(
    r"""(?i)(["']?)(password|passwd|pwd)\1\s*(?:is|=|:)\s*["']?([^\s"'`,;}]+)"""
)
_COOKIE = re.compile(
    r"""(?i)(["']?)(cookie|set-cookie)\1\s*[:=]\s*["']?([^\s"'`,;}]+)"""
)
_TOKEN = re.compile(
    r"""(?i)(["']?)(token|api[_-]?key|secret|bearer)\1\s*[:=]\s*["']?([^\s"'`,;}]+)"""
)
_BEARER = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._\-+/=]+)")
_SESSION = re.compile(r"(?i)\b(session(?:id)?|sid)\s*=\s*([^\s;]+)")
_EMAIL = re.compile(r"(?i)\b([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})\b")


def short_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def _mark(kind: str, value: str) -> str:
    return f"{kind}:{short_hash(value)}"


def redact_text(text: str) -> str:
    """Redact secret-shaped text. The original value is not kept."""

    def sub(
        pattern: re.Pattern[str],
        kind_group: int,
        value_group: int,
        kind: str | None,
        source: str,
    ):
        def replace(match: re.Match[str]) -> str:
            label = kind or match.group(kind_group).lower().replace("-", "_")
            if label == "set_cookie":
                label = "cookie"
            if label.startswith("api"):
                label = "token"
            if label in {"secret", "bearer"}:
                label = "token"
            return _mark(label, match.group(value_group))

        return pattern.sub(replace, source)

    text = sub(_PASSWORD, 2, 3, None, text)
    text = sub(_COOKIE, 2, 3, None, text)
    text = sub(_TOKEN, 2, 3, None, text)
    text = _BEARER.sub(lambda match: _mark("token", match.group(1)), text)
    text = _SESSION.sub(lambda match: _mark("cookie", match.group(2)), text)
    text = _EMAIL.sub(lambda match: _mark("email", match.group(1)), text)
    return text


def _kind_for_key(key: str) -> str:
    normalised = key.lower().replace("-", "_")
    if normalised in {"cookie", "cookies", "session", "sessionid"}:
        return "cookie"
    if normalised in {"password", "passwd", "pwd"}:
        return "password"
    return "token"


def redact_obj(value, key: str | None = None):
    if isinstance(value, dict):
        return {name: redact_obj(item, name) for name, item in value.items()}
    if isinstance(value, list):
        return [redact_obj(item, key) for item in value]
    if isinstance(value, str):
        if key and key.lower().replace("-", "_") in _SECRET_KEYS:
            return _mark(_kind_for_key(key), value)
        return redact_text(value)
    return value
