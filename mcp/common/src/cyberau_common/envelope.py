"""Result envelope and untrusted-text wrapper."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from cyberau_common.secrets import redact

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_INVISIBLE = re.compile(
    "[\u00ad\u061c\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff\U000e0000-\U000e007f]"
)
_WS = re.compile(r"\s+")
_MARKER_OPEN = re.compile(r"<<(?=\s*/?\s*(?:end\b\s*)?untrusted)", re.IGNORECASE)


def untrusted_text(value: str, source: str, max_len: int = 4000) -> str:
    """Strip control, bidi, and zero-width characters, defuse markers, then cap and wrap."""
    cleaned = _INVISIBLE.sub("", _CONTROL.sub("", value))
    cleaned = _WS.sub(" ", cleaned).strip()
    # Break any literal wrapper marker so the text cannot close or reopen the block.
    cleaned = _MARKER_OPEN.sub("< <", cleaned)
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
    return {
        "source": source,
        "source_urls": list(urls),
        "retrieved_at": when,
        "data_as_of": data_as_of,
        "cache": cache,
        "attribution": attribution,
        "untrusted": True,
        "warnings": [redact(str(item)) for item in warnings],
        "data": data,
    }
