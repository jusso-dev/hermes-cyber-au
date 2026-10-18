"""Result envelope and untrusted-text wrapper."""

from __future__ import annotations

import re
import unicodedata
from datetime import UTC, datetime
from functools import lru_cache
from urllib.parse import urlsplit

from cyberau_common.secrets import redact_data

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_INVISIBLE = re.compile("[­؜᠋-᠏​-‏‪-‮⁠-⁩﻿\U000e0000-\U000e007f]")
_WS = re.compile(r"\s+")
# Runs on the folded skeleton of the text (see _skeleton). "\x01" stands for a single
# character that looks like "<<", such as U+00AB or U+226A.
_MARKER_OPEN = re.compile(r"(?:<<|\x01)(?=\s*/?\s*(?:end\b\s*)?untrusted)", re.IGNORECASE)
_DOUBLE_OPEN = "\x01"
# A real wrapper made by untrusted_text. Its inner text has no "<<" left, so the
# non-greedy match stops at its own closing marker.
_WRAPPED = re.compile(r"<<untrusted source=[^\s<>]+>> (?:(?!<<).)*? <<end untrusted>>", re.DOTALL)
_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_URL_BAD_CHARS = re.compile(r"[\s<>\"'`{}|\\^]")
_MAX_WARNING = 500

# Look-alikes that NFKC does not fold. Only the characters a fake wrapper marker needs.
_CONFUSABLES = {
    # Single angle brackets.
    "‹": "<",
    "˂": "<",
    "ᐸ": "<",
    "〈": "<",
    "⟨": "<",
    "\u276c": "<",
    "\u276e": "<",
    "⧼": "<",
    "〈": "<",
    "›": ">",
    "˃": ">",
    "ᐳ": ">",
    "〉": ">",
    "⟩": ">",
    "\u276d": ">",
    "\u276f": ">",
    "⧽": ">",
    "〉": ">",
    # Double angle brackets.
    "«": _DOUBLE_OPEN,
    "≪": _DOUBLE_OPEN,
    "《": _DOUBLE_OPEN,
    "⟪": _DOUBLE_OPEN,
    # Cyrillic, Greek and Armenian letters that look like the Latin letters in
    # "end untrusted source".
    "а": "a",
    "е": "e",
    "о": "o",
    "с": "c",
    "ѕ": "s",
    "ԁ": "d",
    "р": "p",
    "у": "y",
    "Е": "E",
    "О": "O",
    "С": "C",
    "Ѕ": "S",
    "Т": "T",
    "Н": "H",
    "ο": "o",
    "υ": "u",
    "τ": "t",
    "Ο": "O",
    "Τ": "T",
    "Ν": "N",
    "Ε": "E",
    "ո": "n",
    "ս": "u",
    "ց": "g",
    "ᴇ": "E",
    "ɡ": "g",
}


@lru_cache(maxsize=4096)
def _fold_char(char: str) -> str:
    mapped = _CONFUSABLES.get(char)
    if mapped is not None:
        return mapped
    folded = unicodedata.normalize("NFKC", char)
    if len(folded) == 1:
        return _CONFUSABLES.get(folded, folded)
    return char


def _skeleton(text: str) -> str:
    """Same length as text, with look-alike characters folded for marker matching."""
    if text.isascii():
        return text
    return "".join(_fold_char(char) for char in text)


def defuse_markers(text: str) -> str:
    """Break anything that reads as an untrusted wrapper marker, look-alikes included.

    Full-width, small-form, Cyrillic, Greek and other confusable characters are folded
    before matching, so text such as U+FF1C U+FF1C "end untrusted" cannot close a
    wrapper early. Each opening "<<" (or a look-alike) becomes "< <".
    """
    if not text:
        return text
    skeleton = _skeleton(text)
    if "untrusted" not in skeleton.casefold():
        return text
    out: list[str] = []
    last = 0
    for match in _MARKER_OPEN.finditer(skeleton):
        out.append(text[last : match.start()])
        out.append("< <")
        last = match.end()
    if not out:
        return text
    out.append(text[last:])
    return "".join(out)


def untrusted_text(value: str, source: str, max_len: int = 4000) -> str:
    """Normalise and strip invisible characters, defuse markers, then cap and wrap."""
    cleaned = unicodedata.normalize("NFKC", value)
    cleaned = _INVISIBLE.sub("", _CONTROL.sub("", cleaned))
    cleaned = _WS.sub(" ", cleaned).strip()
    # Break any wrapper marker, look-alikes included, so the text cannot close or reopen the block.
    cleaned = defuse_markers(cleaned)
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len]
    return f"<<untrusted source={source}>> {cleaned} <<end untrusted>>"


def safe_url(value: object, *, schemes: tuple[str, ...] = ("https", "http")) -> str | None:
    """Return a feed-supplied URL only when it has an allowed scheme and a sane host.

    Rejects relative links, other schemes (javascript:, data:, file:), user info,
    whitespace, quote and angle characters, non-ASCII text and malformed hosts or ports.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > 2048 or not text.isascii() or _URL_BAD_CHARS.search(text):
        return None
    if _CONTROL.search(text):
        return None
    try:
        parts = urlsplit(text)
        _ = parts.port  # raises ValueError for a malformed port
    except ValueError:
        return None
    if parts.scheme.lower() not in schemes or "@" in parts.netloc:
        return None
    host = (parts.hostname or "").rstrip(".")
    if not host or len(host) > 253:
        return None
    if host.startswith("[") or ":" in host:
        return text
    labels = host.split(".")
    if len(labels) < 2 or not all(_HOST_LABEL.match(label) for label in labels):
        return None
    return text


def _harden_text(value: str) -> str:
    """Defuse markers outside real wrappers. Real wrappers are kept as they are."""
    if value.isascii() and "untrusted" not in value.lower():
        return _CONTROL.sub("", value)
    out: list[str] = []
    last = 0
    for match in _WRAPPED.finditer(value):
        out.append(_harden_plain(value[last : match.start()]))
        # Upstream text can imitate a real wrapper. Inspect its body too, so
        # look-alike closing markers cannot hide inside a matching wrapper.
        opening, _, body = match.group(0).partition(">> ")
        closing = " <<end untrusted>>"
        out.append(opening + ">> " + _harden_plain(body.removesuffix(closing)) + closing)
        last = match.end()
    out.append(_harden_plain(value[last:]))
    return "".join(out)


def _harden_plain(value: str) -> str:
    return defuse_markers(_INVISIBLE.sub("", _CONTROL.sub("", value)))


def harden_data(value):
    """Walk an envelope. Every string outside a real wrapper loses control, bidi and
    zero-width characters and has its marker look-alikes defused.

    This is the backstop for feed fields a connector returns without wrapping, such
    as identifiers, links and upstream error text in warnings.
    """
    if isinstance(value, str):
        return _harden_text(value)
    if isinstance(value, dict):
        return {
            (_harden_text(key) if isinstance(key, str) else key): harden_data(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [harden_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(harden_data(item) for item in value)
    return value


def _warning(item: object) -> str:
    text = _harden_text(str(item))
    if len(text) > _MAX_WARNING:
        # Cap the body before wrapping, so truncation never drops a closing marker.
        budget = _MAX_WARNING - len(untrusted_text("", "warning"))
        text = untrusted_text(text, "warning", budget)
    return text


def harden_envelope(payload: dict) -> dict:
    """Redact secrets, then defuse markers in every string and cap warning length."""
    cleaned = harden_data(redact_data(payload))
    if isinstance(cleaned, dict) and isinstance(cleaned.get("warnings"), list):
        cleaned["warnings"] = [_warning(item) for item in cleaned["warnings"]]
    return cleaned


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
    return harden_envelope(
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
