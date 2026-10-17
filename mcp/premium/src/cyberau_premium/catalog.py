"""Vendor catalogue: terms flags, quota defaults and licence env names."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from cyberau_premium.base import PremiumConnector, QuotaPolicy, TermsProfile
from cyberau_premium.paths import data_dir, package_root

_CACHE_RANK = {"none": 0, "session": 1, "ttl": 2}
_STORE_RANK = {"none": 0, "metadata": 1, "full": 2}
_REDIST_RANK = {"forbidden": 0, "internal": 1, "allowed": 2}
_TERM_FIELDS = (
    "cache",
    "cache_ttl_max_s",
    "store",
    "stix_export",
    "share_outside_profile",
    "redistribution",
    "attribution",
)


class TermsRejected(ValueError):
    """A terms flag was relaxed without a contract reference."""


class VendorSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server: str
    package: str
    name: str
    paid: bool
    milestone: str
    licence_env: list[str] = Field(default_factory=list)
    optional_env: list[str] = Field(default_factory=list)
    terms: TermsProfile
    quota: QuotaPolicy
    routine_share: float = 0.5
    max_pages: int = 5
    tool_prefixes: list[str]


def vendors_path():
    return package_root() / "vendors.yaml"


def load_vendors() -> list[VendorSpec]:
    raw = yaml.safe_load(vendors_path().read_text(encoding="utf-8")) or {}
    vendors = []
    for server, body in (raw.get("vendors") or {}).items():
        payload = dict(body)
        payload["server"] = server
        vendors.append(VendorSpec.model_validate(payload))
    return vendors


def get_vendor(server: str) -> VendorSpec:
    for spec in load_vendors():
        if spec.server == server:
            return spec
    raise KeyError(server)


def vendor_for_tool(tool_name: str) -> VendorSpec | None:
    match: tuple[int, VendorSpec] | None = None
    for spec in load_vendors():
        for prefix in spec.tool_prefixes:
            if tool_name.startswith(prefix) and (match is None or len(prefix) > match[0]):
                match = (len(prefix), spec)
    return None if match is None else match[1]


def bind_vendor(spec: VendorSpec) -> PremiumConnector:
    """Build a connector shell from the catalogue. It does not call the vendor."""
    return PremiumConnector(
        key=spec.server,
        server_name=spec.server,
        attribution=spec.terms.attribution,
        vendor=spec.server,
        licence_env=tuple(spec.licence_env),
        terms=spec.terms,
        quota=spec.quota,
    )


def vendor_config(config: dict | None, server: str) -> dict:
    if not config:
        return {}
    premium = (config.get("cyber_au") or {}).get("premium") or {}
    block = premium.get(server) or {}
    return block if isinstance(block, dict) else {}


def apply_terms(spec: VendorSpec, config: dict | None, *, audit_path=None) -> TermsProfile:
    override = dict(vendor_config(config, spec.server).get("terms") or {})
    contract_ref = override.pop("contract_ref", None)
    if not override:
        return spec.terms
    unknown = set(override) - set(_TERM_FIELDS)
    if unknown:
        raise TermsRejected(f"unknown terms fields: {', '.join(sorted(unknown))}")
    try:
        proposed = TermsProfile.model_validate({**spec.terms.model_dump(), **override})
    except ValidationError as exc:
        raise TermsRejected(f"invalid terms: {exc.error_count()} problem(s)") from exc
    relaxed = _relaxed_fields(spec.terms, proposed)
    if relaxed:
        if not isinstance(contract_ref, str) or not contract_ref.strip():
            raise TermsRejected("relaxing terms requires contract_ref")
        _audit(spec.server, contract_ref.strip(), relaxed, audit_path)
    return proposed


def _relaxed_fields(current: TermsProfile, proposed: TermsProfile) -> list[str]:
    relaxed: list[str] = []
    if _CACHE_RANK[proposed.cache] > _CACHE_RANK[current.cache]:
        relaxed.append("cache")
    if proposed.cache == "ttl" and proposed.cache_ttl_max_s > current.cache_ttl_max_s:
        relaxed.append("cache_ttl_max_s")
    if _STORE_RANK[proposed.store] > _STORE_RANK[current.store]:
        relaxed.append("store")
    if proposed.stix_export and not current.stix_export:
        relaxed.append("stix_export")
    if proposed.share_outside_profile and not current.share_outside_profile:
        relaxed.append("share_outside_profile")
    if _REDIST_RANK[proposed.redistribution] > _REDIST_RANK[current.redistribution]:
        relaxed.append("redistribution")
    return relaxed


def _audit(vendor: str, contract_ref: str, relaxed: list[str], audit_path) -> None:
    path = audit_path or (data_dir() / "audit.jsonl")
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "at": datetime.now().astimezone().isoformat(),
        "event": "terms_relaxed",
        "vendor": vendor,
        "contract_ref": contract_ref,
        "relaxed": relaxed,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, separators=(",", ":")) + "\n")


def quota_override(spec: VendorSpec, config: dict | None) -> dict[str, Any]:
    raw = vendor_config(config, spec.server).get("quota") or {}
    return raw if isinstance(raw, dict) else {}
