"""Drop findings a licence will not share outside the owner's channel."""

from __future__ import annotations

from cyberau_premium.base import ExposureFinding, TermsProfile


def filter_for_delivery(
    findings: list[ExposureFinding],
    terms_by_vendor: dict[str, TermsProfile],
    *,
    target: str,
    owner: str,
) -> list[ExposureFinding]:
    if target == owner:
        return list(findings)
    kept = []
    for finding in findings:
        terms = terms_by_vendor[finding.vendor]
        if terms.share_outside_profile:
            kept.append(finding)
    return kept
