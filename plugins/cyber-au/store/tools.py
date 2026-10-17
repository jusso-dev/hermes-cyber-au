"""In-process intel tools.

``intel_search``, ``intel_get``, ``intel_add_observation`` and
``intel_export_stix`` are the tool surface for this store. Feed text stays
inside the result envelope.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from .api import KINDS, ensure_source, lookup, search, upsert_indicator
from .canonical import require_tlp, utc_now
from .stix import export_stix
from .text import clean_untrusted


def intel_search(
    query: str,
    kinds: Sequence[str] | None = None,
    since: str | None = None,
    limit: int = 20,
    path: str | Path | None = None,
) -> dict:
    """Search the local store. ``limit`` is at most 100."""
    chosen = KINDS if kinds is None else kinds
    rows = search(query, kinds=chosen, since=since, limit=limit, path=path)
    return _envelope(rows)


def intel_get(
    id_or_value: str,
    type: str | None = None,
    path: str | Path | None = None,
) -> dict:
    """Fetch by STIX id, CVE id, advisory id, or indicator value."""
    return _envelope(lookup(id_or_value, type=type, path=path))


def intel_add_observation(
    type: str,
    value: str,
    *,
    verdict: str | None = None,
    confidence: int | None = None,
    tags: Sequence[str] = (),
    tlp: str = "AMBER",
    note: str | None = None,
    path: str | Path | None = None,
) -> dict:
    """Record an analyst observation. ``source_id`` is ``analyst``.

    The marking defaults to ``AMBER``. Repeating the same type, value,
    verdict, confidence, tags, marking and note updates that observation
    instead of inserting another row.
    """
    if not isinstance(type, str) or not isinstance(value, str):
        raise ValueError("type and value are required")
    if note is not None and not isinstance(note, str):
        raise ValueError("note must be a string")
    marking = require_tlp(tlp)
    cleaned_note = "" if note is None else clean_untrusted(note)
    tag_list = () if tags is None else tags
    payload = {
        "confidence": confidence,
        "note": cleaned_note,
        "tags": list(tag_list),
        "tlp": marking,
        "type": type,
        "value": value.strip(),
        "verdict": verdict,
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    ensure_source("analyst", name="Analyst", default_tlp="AMBER", path=path)
    record_id = upsert_indicator(
        type,
        value,
        source="analyst",
        observed_at=utc_now(),
        raw=raw,
        verdict=verdict,
        confidence=confidence,
        tags=tag_list,
        tlp=marking,
        note=cleaned_note or None,
        path=path,
    )
    return _envelope(lookup(record_id, path=path))


def intel_export_stix(
    since: str | None = None,
    kinds: Sequence[str] | None = None,
    max_tlp: str | None = None,
    path: str | None = None,
    *,
    store: str | Path | None = None,
) -> dict:
    """Export a STIX 2.1 bundle. ``max_tlp`` defaults to CLEAR.

    ``path``, when set, is a ``.json`` file under ``plugin-data/cyber-au/exports/``.
    ``AMBER`` is included only when ``max_tlp`` is ``AMBER``. ``AMBER+STRICT``
    and ``RED`` are never included.
    """
    result = export_stix(
        since=since,
        kinds=kinds,
        max_tlp=max_tlp,
        output=path,
        store=store,
    )
    payload = _envelope(
        {
            "bundle": result["bundle"],
            "explicit_max_tlp": result["explicit_max_tlp"],
            "format": "stix21",
            "max_tlp": result["max_tlp"],
            "object_count": result["object_count"],
            "omitted_above_tlp": result["omitted_above_tlp"],
            "omitted_unsupported": result["omitted_unsupported"],
            "path": result["output"],
        }
    )
    if result["omitted_above_tlp"]:
        payload["warnings"].append(
            f"omitted {result['omitted_above_tlp']} records above max_tlp {result['max_tlp']}"
        )
    if result["omitted_unsupported"]:
        payload["warnings"].append(
            f"omitted {result['omitted_unsupported']} asn or cidr indicators"
        )
    return payload


def _envelope(data: object) -> dict:
    return {
        "source": "intel-store",
        "source_urls": [],
        "retrieved_at": utc_now(),
        "data_as_of": None,
        "cache": "snapshot",
        "attribution": "Local threat intel store",
        "untrusted": True,
        "warnings": [],
        "data": data,
    }
