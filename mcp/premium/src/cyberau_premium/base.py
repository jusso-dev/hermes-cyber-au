"""Shared types for paid, bring-your-own-licence connectors."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import date, datetime
from typing import Literal

from cyberau_common.secrets import lookup
from cyberau_common.server import Connector, Probe
from pydantic import BaseModel, ConfigDict, Field

CacheMode = Literal["none", "session", "ttl"]
StoreMode = Literal["none", "metadata", "full"]
Redistribution = Literal["forbidden", "internal", "allowed"]
Kind = Literal[
    "infostealer_credential",
    "breach_credential",
    "leak_site_claim",
    "data_leak_disclosure",
    "dark_web_mention",
    "typosquat_domain",
    "brand_impersonation",
    "attack_surface_issue",
]
SubjectType = Literal["domain", "abn", "brand", "email_domain", "ip"]
Confidence = Literal["vendor_confirmed", "vendor_reported", "unverified_claim"]
LicenceScope = Literal["session_only", "store_metadata", "store_full"]

_SCOPE_FOR_STORE: dict[StoreMode, LicenceScope] = {
    "none": "session_only",
    "metadata": "store_metadata",
    "full": "store_full",
}
_SCOPE_RANK = {"session_only": 0, "store_metadata": 1, "store_full": 2}


class TermsProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cache: CacheMode
    cache_ttl_max_s: int = 0
    store: StoreMode
    stix_export: bool = False
    share_outside_profile: bool = False
    redistribution: Redistribution = "forbidden"
    attribution: str


class QuotaPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    calls_per_day: int | None = None
    calls_per_month: int | None = None
    cost_units_per_call: float = 1.0
    monthly_budget_units: float | None = None
    approval_above_units: float | None = None
    hard_stop: bool = True


class HealthResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    configured: bool
    ok: bool
    detail: str


class Subject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: SubjectType
    value: str
    watchlist_entry: str | None = None


class ExposureFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    vendor: str
    kind: Kind
    subject: Subject
    observed_at: datetime
    licence_scope: LicenceScope
    confidence: Confidence
    counts: dict[str, int] | None = None
    data_classes: list[str] | None = None
    first_seen: datetime | None = None
    source_ref: str | None = None
    stix_exportable: bool = False
    contains_personal_information: bool = False


class Watchlist(BaseModel):
    model_config = ConfigDict(extra="ignore")

    organisation: str | None = None
    abns: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    email_domains: list[str] = Field(default_factory=list)
    brands: list[str] = Field(default_factory=list)
    subsidiaries: list[dict] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)

    def known_subjects(self) -> set[str]:
        values: set[str] = set(self.abns)
        values.update(self.domains)
        values.update(self.email_domains)
        values.update(self.brands)
        for item in self.subsidiaries:
            name = item.get("name")
            if isinstance(name, str):
                values.add(name)
            for domain in item.get("domains") or []:
                if isinstance(domain, str):
                    values.add(domain)
        excluded = {item.casefold() for item in self.exclude}
        return {item.casefold() for item in values if item.casefold() not in excluded}


@dataclass
class PremiumConnector(Connector):
    """Base class every premium connector implements. This package does not call a vendor."""

    vendor: str = ""
    licence_env: tuple[str, ...] = ()
    terms: TermsProfile | None = None
    quota: QuotaPolicy | None = None

    def __post_init__(self) -> None:
        if not self.vendor:
            raise ValueError("vendor is required")
        if self.terms is None or self.quota is None:
            raise ValueError("terms and quota are required")

    def exposure_for(self, watchlist: Watchlist, since: date) -> list[ExposureFinding]:
        """Vendor packages fill this in. The shared interface does not call upstream."""
        raise NotImplementedError(
            f"{self.vendor} has no vendor client in the shared premium interface"
        )

    def health_result(self, *, live: bool = False) -> HealthResult:
        missing = [name for name in self.licence_env if lookup(name) is None]
        if missing:
            return HealthResult(configured=False, ok=True, detail="not configured")
        if not live:
            return HealthResult(configured=True, ok=True, detail="offline ok")
        return HealthResult(
            configured=True,
            ok=True,
            detail="configured; the vendor connector performs the cheap authenticated check",
        )

    def health(self, *, live: bool = False, check_schema: bool = False) -> Probe:
        if check_schema:
            return Probe(self.key, True, "exposure finding schema is bundled")
        result = self.health_result(live=live)
        return Probe(self.key, result.ok, result.detail)


def finding_id(vendor: str, kind: str, subject_value: str, source_ref: str | None) -> str:
    material = f"{vendor}|{kind}|{subject_value}|{source_ref or ''}"
    return hashlib.sha256(material.encode()).hexdigest()


def canonical_finding(finding: ExposureFinding) -> ExposureFinding:
    """Force the documented finding id and the leak-site confidence label."""
    expected = finding_id(
        finding.vendor,
        finding.kind,
        finding.subject.value,
        finding.source_ref,
    )
    updates: dict = {}
    if finding.finding_id != expected:
        updates["finding_id"] = expected
    if finding.kind == "leak_site_claim" and finding.confidence != "unverified_claim":
        updates["confidence"] = "unverified_claim"
    if not updates:
        return finding
    return finding.model_copy(update=updates)


def clamp_to_terms(finding: ExposureFinding, terms: TermsProfile) -> ExposureFinding:
    """Drop rights the licence does not grant. Never widen them."""
    allowed = _SCOPE_FOR_STORE[terms.store]
    updates: dict = {}
    if _SCOPE_RANK[finding.licence_scope] > _SCOPE_RANK[allowed]:
        updates["licence_scope"] = allowed
    if not terms.stix_export and finding.stix_exportable:
        updates["stix_exportable"] = False
    if not updates:
        return finding
    return finding.model_copy(update=updates)
