"""Provenance footer: where each piece of an answer came from and how old it is.

Every connector tool returns an envelope with ``source``, ``retrieved_at``,
``data_as_of``, ``cache`` and ``warnings`` (see ``envelope.py``). ``footer`` turns
the envelopes an answer used into a short block that skills put at the end of the
answer, so the reader can see each source, its age, and whether it was live, cached,
stale or a snapshot.

    cyberau-mcp provenance results.json      # one envelope, a list, or a pack
    cyberau-mcp provenance - < results.json

Warnings are connector text and stay data: they are flattened, capped and quoted,
never followed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable
from datetime import UTC, datetime

from cyberau_common.envelope import untrusted_text

CACHE_WORDS = {
    "miss": "live",
    "hit": "cached",
    "stale": "stale cache (live fetch failed)",
    "snapshot": "snapshot",
}
WARNING_LIMIT = 160
MAX_DEPTH = 6
_WS = re.compile(r"\s+")


def _time(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment.astimezone(UTC) if moment.tzinfo else moment.replace(tzinfo=UTC)


def age(then: datetime | None, now: datetime) -> str:
    if then is None:
        return "age unknown"
    seconds = int((now - then).total_seconds())
    if seconds < 0:
        return "dated in the future"
    if seconds < 3600:
        return f"{seconds // 60}m old"
    if seconds < 172800:
        return f"{seconds // 3600}h old"
    return f"{seconds // 86400}d old"


def is_envelope(value: object) -> bool:
    return isinstance(value, dict) and "source" in value and "cache" in value


def find_envelopes(value: object, depth: int = 0) -> list[dict]:
    """Envelopes anywhere in a JSON value: one envelope, a list, or a pack of them."""
    if depth > MAX_DEPTH:
        return []
    if is_envelope(value):
        return [value]  # do not look inside the data of an envelope
    found: list[dict] = []
    if isinstance(value, dict):
        for item in value.values():
            found.extend(find_envelopes(item, depth + 1))
    elif isinstance(value, list):
        for item in value:
            found.extend(find_envelopes(item, depth + 1))
    return found


def _flat(value: object, limit: int = WARNING_LIMIT) -> str:
    text = _WS.sub(" ", str(value)).strip().replace("`", "'")
    if len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    return text


def describe(envelope: dict, now: datetime) -> str:
    """One footer line for one envelope."""
    source = _flat(envelope.get("source") or "unknown source", 60)
    cache = str(envelope.get("cache") or "")
    state = CACHE_WORDS.get(cache, f"cache {_flat(cache, 20)}" if cache else "cache unknown")
    retrieved = _time(envelope.get("retrieved_at"))
    as_of = _time(envelope.get("data_as_of"))
    parts = [f"{source}: {state}"]
    if retrieved:
        parts.append(f"retrieved {retrieved.strftime('%Y-%m-%d %H:%M')} UTC")
    if as_of:
        parts.append(f"data as of {as_of.strftime('%Y-%m-%d %H:%M')} UTC")
    parts.append(age(as_of or retrieved, now))
    line = ", ".join(parts)
    warnings = [_flat(item) for item in envelope.get("warnings") or [] if str(item).strip()]
    if warnings:
        line += ". Warnings (connector text): " + "; ".join(
            untrusted_text(item, "provenance-warning", max_len=WARNING_LIMIT) for item in warnings
        )
    return line


def footer(envelopes: Iterable[dict], now: datetime | None = None) -> str:
    """The provenance block for an answer. Duplicate lines are shown once."""
    moment = now or datetime.now(UTC)
    lines: list[str] = []
    for envelope in envelopes:
        line = describe(envelope, moment)
        if line not in lines:
            lines.append(line)
    if not lines:
        return "Provenance: no connector data was used in this answer.\n"
    body = "\n".join(f"- {line}" for line in lines)
    return f"Provenance:\n{body}\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cyberau-mcp provenance",
        description="Print the provenance footer for connector results.",
    )
    parser.add_argument("path", nargs="?", default="-", help="JSON file, or - for stdin")
    parser.add_argument("--now", default="", help="Clock for ages (ISO 8601), for tests")
    args = parser.parse_args(argv)
    try:
        if args.path == "-":
            raw = sys.stdin.read()
        else:
            with open(args.path, encoding="utf-8") as handle:
                raw = handle.read()
        value = json.loads(raw)
    except (OSError, ValueError) as exc:
        print(f"provenance: cannot read input: {exc.__class__.__name__}", file=sys.stderr)
        return 1
    now = _time(args.now) if args.now else None
    sys.stdout.write(footer(find_envelopes(value), now))
    return 0
