"""Result envelope and untrusted-text wrapper."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from cyberau_common.secrets import redact_data

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069\u200b-\u200f]")
_WS = re.compile(r"\s+")


def untrusted_text(value: str, source: str, max_len: int = 4000) -> str:
    """Strip control and bidi characters, collapse whitespace, and wrap the text."""
    cleaned = _BIDI.sub("", _CONTROL.sub("", value))
    cleaned = _WS.sub(" ", cleaned).strip()
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len]
    return f"<<untrusted source={source}>> {cleaned} <<end untrusted>>"


def envelope(
    source: str,
    data,
    *,
    urls: list[str] | tuple[str, ...] = (),
    cache: str,
    data_as_of: str | None = None,
    warnings: tuple[str, ...] | list[str] = (),
    attribution: str = "",
    retrieved_at: str | None = None,
) -> dict:
    """Build the JSON object every connector tool returns."""
    if cache not in {"hit", "miss", "stale", "snapshot"}:
        raise ValueError(f"unknown cache state: {cache}")
    when = retrieved_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return redact_data(
        {
            "source": source,
            "source_urls": list(urls),
            "retrieved_at": when,
            "data_as_of": data_as_of,
            "cache": cache,
            "attribution": attribution,
            "untrusted": True,
            "warnings": [str(item) for item in warnings],
            "data": data,
        }
    )
