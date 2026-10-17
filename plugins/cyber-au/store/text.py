"""Wrap untrusted feed and analyst text before it is stored."""

from __future__ import annotations

import re

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069\u200b-\u200f]")
_WS = re.compile(r"\s+")
_MARKER = re.compile(r"<<(\s*(?:end\s+)?untrusted)", re.IGNORECASE)
_WRAPPED = re.compile(r"<<untrusted source=[^>]{1,80}>> (.*) <<end untrusted>>", re.DOTALL)


def clean_untrusted(value: str, max_len: int = 4000) -> str:
    """Strip control and bidi characters and collapse whitespace."""
    if not isinstance(value, str):
        raise ValueError("untrusted text must be a string")
    cleaned = _BIDI.sub("", _CONTROL.sub("", value))
    cleaned = _WS.sub(" ", cleaned).strip()
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len]
    return cleaned


def defuse_markers(value: str) -> str:
    """Break up ``<<untrusted`` and ``<<end untrusted`` look-alikes in feed text."""
    return _MARKER.sub(r"< <\1", value)


def wrap_untrusted(value: str, source: str, max_len: int = 4000) -> str:
    """Return cleaned text inside the shared untrusted envelope markers.

    Marker look-alikes in the text are broken up so feed text cannot close the
    envelope early and place its own words outside it.
    """
    cleaned = defuse_markers(clean_untrusted(value, max_len=max_len))
    return f"<<untrusted source={source}>> {cleaned} <<end untrusted>>"


def unwrap_untrusted(value: str) -> str | None:
    """Return the inner text when ``value`` is one wrapped untrusted string."""
    if not isinstance(value, str):
        return None
    match = _WRAPPED.fullmatch(value)
    if match is None:
        return None
    return match.group(1)


def indexable_text(value: str) -> str:
    """Text placed in FTS. Wrapper markers are not indexed."""
    match = _WRAPPED.fullmatch(value)
    if match:
        return match.group(1)
    return value
