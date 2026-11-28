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
                    "domain, ABN, brand or watchlist entry id; default all watchlist entries"
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


FINDING_SCHEMA = {
    "name": "cyber_au_exposure_finding",
    "description": (
        "Read one stored exposure finding by id from the local exposures table, for an "
        "NDB assessment draft. Metadata only: kind, subject, data classes, counts, first "
        "seen, confidence. Calls no vendor and contacts no one."
    ),
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "finding_id": {"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,128}$"},
        },
        "required": ["finding_id"],
    },
}

TREND_SCHEMA = {
    "name": "cyber_au_exposure_trend",
    "description": (
        "Counts only: exposure findings in the local exposures table for the last 7 days "
        "against the 7 days before, by kind. No subjects, names or values. Calls no vendor."
    ),
    "parameters": {"type": "object", "additionalProperties": False, "properties": {}},
}


def handle_finding(**kwargs) -> str:
    from cyberau_org_exposure.briefing import finding_payload

    value = kwargs.get("finding_id")
    if not isinstance(value, str) or not value.strip():
        value = ""
    return json.dumps(finding_payload(value.strip()))


def handle_trend(**_kwargs) -> str:
    from cyberau_common.envelope import envelope

    from cyberau_org_exposure.briefing import ATTRIBUTION, brief_payload

    counted = brief_payload()["data"]["trend"]
    return json.dumps(envelope("org-exposure", counted, cache="snapshot", attribution=ATTRIBUTION))
