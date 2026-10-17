"""Intel store tools. The store itself is not installed yet."""

from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)

STORE_NOT_INSTALLED = "The intel store is not installed yet."
EXPORT_NOT_INSTALLED = "STIX export is not installed yet."

_INDICATOR_TYPES = [
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "email",
    "md5",
    "sha1",
    "sha256",
    "asn",
    "cidr",
]
_VERDICTS = ["malicious", "suspicious", "benign", "unknown"]
_TLP = ["CLEAR", "GREEN", "AMBER"]
_KINDS = ["indicator", "advisory", "vulnerability"]


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


def _result(message: str) -> str:
    return json.dumps({"installed": False, "message": message}, sort_keys=True)


def _safe(message: str, _args: dict | None = None, **kwargs) -> str:
    """Return the not-installed result. Arguments are ignored and never logged."""
    del _args, kwargs
    try:
        return _result(message)
    except Exception:
        logger.exception("cyber-au intel tool failed")
        return json.dumps({"installed": False, "message": message}, sort_keys=True)


def intel_search(args: dict | None = None, **kwargs) -> str:
    """Search the local threat intel store."""
    return _safe(STORE_NOT_INSTALLED, args, **kwargs)


def intel_get(args: dict | None = None, **kwargs) -> str:
    """Fetch one store record by id or value."""
    return _safe(STORE_NOT_INSTALLED, args, **kwargs)


def intel_add_observation(args: dict | None = None, **kwargs) -> str:
    """Record an analyst observation. Nothing is written while the store is absent."""
    return _safe(STORE_NOT_INSTALLED, args, **kwargs)


def intel_export_stix(args: dict | None = None, **kwargs) -> str:
    """Export store records as STIX 2.1. Export is not installed yet."""
    return _safe(EXPORT_NOT_INSTALLED, args, **kwargs)


INTEL_SEARCH = _schema(
    "intel_search",
    "Search the local threat intel store. The store is not installed yet.",
    {
        "query": {"type": "string", "description": "Search text"},
        "kinds": {
            "type": "array",
            "items": {"type": "string", "enum": _KINDS},
            "description": "Record kinds to include",
        },
        "since": {
            "type": "string",
            "description": "Only records on or after this date (YYYY-MM-DD)",
        },
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": 100,
            "description": "Maximum results",
        },
    },
    ["query"],
)
INTEL_GET = _schema(
    "intel_get",
    "Fetch one local threat intel record. The store is not installed yet.",
    {
        "id_or_value": {"type": "string", "description": "Store id or indicator value"},
        "type": {"type": "string", "enum": _INDICATOR_TYPES, "description": "Indicator type"},
    },
    ["id_or_value"],
)
INTEL_ADD_OBSERVATION = _schema(
    "intel_add_observation",
    "Record an analyst observation. The store is not installed yet, so nothing is written.",
    {
        "type": {"type": "string", "enum": _INDICATOR_TYPES},
        "value": {"type": "string", "description": "Indicator value"},
        "verdict": {"type": "string", "enum": _VERDICTS},
        "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
        "tags": {"type": "array", "items": {"type": "string"}},
        "tlp": {"type": "string", "enum": _TLP},
        "note": {"type": "string", "description": "Analyst note"},
    },
    ["type", "value"],
)
INTEL_EXPORT_STIX = _schema(
    "intel_export_stix",
    "Export the local threat intel store as STIX 2.1. STIX export is not installed yet.",
    {
        "since": {"type": "string", "description": "Only records on or after this date"},
        "kinds": {
            "type": "array",
            "items": {"type": "string", "enum": _KINDS},
        },
        "max_tlp": {"type": "string", "enum": _TLP},
        "path": {
            "type": "string",
            "description": "Write under plugin-data/cyber-au/exports/ only",
        },
    },
    [],
)

_TOOLS = (
    ("intel_search", INTEL_SEARCH, intel_search),
    ("intel_get", INTEL_GET, intel_get),
    ("intel_add_observation", INTEL_ADD_OBSERVATION, intel_add_observation),
    ("intel_export_stix", INTEL_EXPORT_STIX, intel_export_stix),
)


def register_store(ctx) -> None:
    """Register the intel_* tools. Handlers do not read or write the store."""
    for name, schema, handler in _TOOLS:
        ctx.register_tool(
            name=name,
            toolset="cyber-au",
            schema=schema,
            handler=handler,
            description=schema["description"],
        )
