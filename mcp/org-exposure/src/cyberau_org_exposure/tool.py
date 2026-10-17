"""Plugin tool that wraps the org exposure query."""

from __future__ import annotations

import json

from cyberau_org_exposure.service import run_tool

SCHEMA = {
    "name": "cyber_au_org_exposure",
    "description": (
        "Check whether the user's own organisation is exposed on enabled premium "
        "feeds and the free ransomware tracker. Searches only the org exposure "
        "watchlist. Does not search a third party, print secrets, or contact anyone."
    ),
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "subject": {
                "type": "string",
                "description": (
                    "domain, ABN, brand or watchlist entry id; "
                    "default all watchlist entries"
                ),
            },
            "since": {"type": "string", "format": "date"},
            "kinds": {"type": "array", "items": {"type": "string"}},
            "vendors": {"type": "array", "items": {"type": "string"}},
        },
        "required": [],
    },
}


def handle(**kwargs) -> str:
    """Return the query envelope. Host metadata beyond the schema is ignored."""
    payload = {
        key: kwargs[key] for key in ("subject", "since", "kinds", "vendors") if key in kwargs
    }
    return json.dumps(run_tool(payload))
