"""Hand claims to Oh My Hermes source trust when that package is importable.

OMH's own tool refuses to invent a ceiling result when the backend is missing.
This module does the same. It does not reimplement the ceiling table.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

UNAVAILABLE = (
    "The OMH package backend is not importable, so the source-trust ceiling did not run. "
    "No summary is returned: an unenforced answer must not read as an enforced one."
)


def offer_claims(topic: str, claims: list[dict[str, Any]]) -> dict[str, Any]:
    """Ask omh.workflows.source_trust to mint claims. Degrade closed if it is absent."""
    try:
        from omh.workflows.source_trust import (  # type: ignore
            SOURCE_TRUST_CLAIM_BOUNDARY,
            SourceTrustError,
            build_source_trust_claim,
            summarize_source_trust,
        )
    except (ImportError, ModuleNotFoundError):
        return {
            "plugin_tool": "omh_source_trust",
            "degraded": True,
            "ceiling_applied": False,
            "reason": UNAVAILABLE,
            "evidence_class": "prepared_not_observed",
        }

    minted = []
    refused = []
    recorded_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for index, row in enumerate(claims[:64]):
        try:
            minted.append(
                build_source_trust_claim(
                    tier=str(row.get("tier") or ""),
                    claim_kind=str(row.get("claim_kind") or ""),
                    claim=str(row.get("claim") or ""),
                    recorded_at=str(row.get("recorded_at") or recorded_at),
                    source_ref=str(row.get("source_id") or ""),
                )
            )
        except SourceTrustError as exc:
            refused.append({"index": index, "reason": str(exc)[:200]})
    try:
        summary = summarize_source_trust(topic=topic or "unnamed topic", claims=minted)
    except SourceTrustError as exc:
        return {
            "plugin_tool": "omh_source_trust",
            "degraded": True,
            "ceiling_applied": False,
            "reason": str(exc)[:200],
            "evidence_class": "prepared_not_observed",
        }
    return {
        "plugin_tool": "omh_source_trust",
        "degraded": False,
        "ceiling_applied": True,
        "summary": summary,
        "refused_claims": refused[:8],
        "claim_boundary": SOURCE_TRUST_CLAIM_BOUNDARY,
        "evidence_class": "prepared_not_observed",
    }
