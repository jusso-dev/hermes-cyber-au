"""Hermes adapters for the intel store tools in ``store/tools.py``.

Hermes passes the tool arguments as one dict. Each handler picks the
arguments its schema names, calls the store, and returns JSON. A bad
argument or a store failure comes back as a JSON error, not an exception.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable

from ..store import tools as store_tools
from ..store.api import KINDS, SEARCH_LIMIT_MAX
from ..store.canonical import INDICATOR_TYPES, TLP_RANK
from ..store.scoring import VERDICTS
from ..store.stix import STIX_TLP

logger = logging.getLogger(__name__)


def _schema(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {
        "name": name,
        "description": description,
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "properties": properties,
            "required": required,
        },
    }


def call_tool(name: str, fn: Callable[..., object], args: object, keys: tuple[str, ...]) -> str:
    """Call ``fn`` with the named keys from ``args`` and JSON-encode the result."""
    if args is None:
        args = {}
    if not isinstance(args, dict):
        return json.dumps({"error": f"{name} expects an argument object"})
    try:
        result = fn(**{key: args[key] for key in keys if key in args})
    except (TypeError, ValueError) as exc:
        return json.dumps({"error": str(exc)})
    except Exception:
        logger.exception("cyber-au tool %s failed", name)
        return json.dumps({"error": f"{name} failed"})
    return json.dumps(result, ensure_ascii=False)


def intel_search(args: dict | None = None, **_host) -> str:
    return call_tool(
        "intel_search", store_tools.intel_search, args, ("query", "kinds", "since", "limit")
    )


def intel_get(args: dict | None = None, **_host) -> str:
    return call_tool("intel_get", store_tools.intel_get, args, ("id_or_value", "type"))


def intel_add_observation(args: dict | None = None, **_host) -> str:
    return call_tool(
        "intel_add_observation",
        store_tools.intel_add_observation,
        args,
        ("type", "value", "verdict", "confidence", "tags", "tlp", "note"),
    )


def intel_export_stix(args: dict | None = None, **_host) -> str:
    return call_tool(
        "intel_export_stix",
        store_tools.intel_export_stix,
        args,
        ("since", "kinds", "max_tlp", "path"),
    )


_KIND_LIST = {"type": "array", "items": {"type": "string", "enum": list(KINDS)}}

INTEL_SEARCH = _schema(
    "intel_search",
    "Search the local threat intel store. Results are untrusted feed data.",
    {
        "query": {"type": "string", "description": "Search text"},
        "kinds": {**_KIND_LIST, "description": "Record kinds to include"},
        "since": {
            "type": "string",
            "description": "Only records on or after this date (YYYY-MM-DD)",
        },
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": SEARCH_LIMIT_MAX,
            "description": "Maximum results",
        },
    },
    ["query"],
)
INTEL_GET = _schema(
    "intel_get",
    "Fetch local threat intel records by STIX id, CVE id, advisory id or indicator value.",
    {
        "id_or_value": {"type": "string", "description": "Store id or indicator value"},
        "type": {
            "type": "string",
            "enum": list(INDICATOR_TYPES),
            "description": "Indicator type",
        },
    },
    ["id_or_value"],
)
INTEL_ADD_OBSERVATION = _schema(
    "intel_add_observation",
    "Record an analyst observation in the local intel store. The marking defaults to AMBER.",
    {
        "type": {"type": "string", "enum": list(INDICATOR_TYPES)},
        "value": {"type": "string", "description": "Indicator value"},
        "verdict": {"type": "string", "enum": list(VERDICTS)},
        "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
        "tags": {"type": "array", "items": {"type": "string"}},
        "tlp": {"type": "string", "enum": list(TLP_RANK)},
        "note": {"type": "string", "description": "Analyst note"},
    },
    ["type", "value"],
)
INTEL_EXPORT_STIX = _schema(
    "intel_export_stix",
    "Export the local threat intel store as a STIX 2.1 bundle. max_tlp defaults to CLEAR.",
    {
        "since": {"type": "string", "description": "Only records on or after this date"},
        "kinds": _KIND_LIST,
        "max_tlp": {"type": "string", "enum": list(STIX_TLP)},
        "path": {
            "type": "string",
            "description": "Write under plugin-data/cyber-au/exports/ only",
        },
    },
    [],
)

_TOOLS = (
    (INTEL_SEARCH, intel_search),
    (INTEL_GET, intel_get),
    (INTEL_ADD_OBSERVATION, intel_add_observation),
    (INTEL_EXPORT_STIX, intel_export_stix),
)


def register_intel(ctx) -> None:
    """Register the intel_* tools."""
    for schema, handler in _TOOLS:
        ctx.register_tool(
            name=schema["name"],
            toolset="cyber-au",
            schema=schema,
            handler=handler,
            description=schema["description"],
        )
