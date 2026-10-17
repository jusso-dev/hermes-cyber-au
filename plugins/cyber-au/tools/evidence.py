"""Evidence import. The importer is not installed yet."""

from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)

EVIDENCE_NOT_INSTALLED = "Evidence import is not installed yet."

EVIDENCE_IMPORT = {
    "name": "evidence_import",
    "description": (
        "Import an assessment report as evidence. Evidence import is not installed yet, "
        "so the path is not opened."
    ),
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "path": {"type": "string", "description": "Path of a local assessment report"},
        },
        "required": ["path"],
    },
}


def evidence_import(args: dict | None = None, **kwargs) -> str:
    """Return the not-installed result. The path is not opened and not echoed."""
    del args, kwargs
    try:
        return json.dumps(
            {"installed": False, "message": EVIDENCE_NOT_INSTALLED},
            sort_keys=True,
        )
    except Exception:
        logger.exception("cyber-au evidence import failed")
        return '{"installed": false, "message": "Evidence import is not installed yet."}'


def register_evidence(ctx) -> None:
    """Register evidence_import."""
    ctx.register_tool(
        name="evidence_import",
        toolset="cyber-au",
        schema=EVIDENCE_IMPORT,
        handler=evidence_import,
        description=EVIDENCE_IMPORT["description"],
    )
