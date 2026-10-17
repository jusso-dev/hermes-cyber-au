"""Synthetic findings for tests. No real victims or credentials."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from cyberau_premium.base import ExposureFinding, Subject, TermsProfile, finding_id
from cyberau_premium.paths import package_root

SCHEMA = json.loads(
    (package_root() / "schema" / "exposure_finding.json").read_text(encoding="utf-8")
)
OBSERVED = datetime(2026, 6, 1, 0, 0, tzinfo=UTC)


def sample_finding(vendor: str, terms: TermsProfile | None = None, **updates) -> ExposureFinding:
    kind = updates.pop("kind", "infostealer_credential")
    subject_value = updates.pop("subject_value", "example.com.au")
    source_ref = updates.pop("source_ref", "rec-1")
    confidence = updates.pop("confidence", "vendor_reported")
    scope = "store_metadata"
    if terms is not None and terms.store == "full":
        scope = "store_full"
    if terms is not None and terms.store == "none":
        scope = "session_only"
    finding = ExposureFinding(
        finding_id=finding_id(vendor, kind, subject_value, source_ref),
        vendor=vendor,
        kind=kind,
        subject=Subject(type="domain", value=subject_value, watchlist_entry="wl-1"),
        observed_at=updates.pop("observed_at", OBSERVED),
        first_seen=updates.pop("first_seen", OBSERVED),
        licence_scope=updates.pop("licence_scope", scope),
        confidence=confidence,
        counts=updates.pop("counts", {"employees": 2}),
        data_classes=updates.pop("data_classes", ["email address"]),
        source_ref=source_ref,
        stix_exportable=updates.pop("stix_exportable", False),
        contains_personal_information=updates.pop("contains_personal_information", False),
    )
    if updates:
        raise TypeError(f"unknown finding fields: {sorted(updates)}")
    return finding
