"""Load and validate the user-owned org exposure watchlist.

The file is created on the user's machine. It is not shipped.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from cyberau_org_exposure.abn import checksum_ok, normalise_abn, profile_home

CONFIDENCE = ("vendor_confirmed", "vendor_reported", "unverified_claim")
ALERT_KINDS = (
    "infostealer_credential",
    "breach_credential",
    "leak_site_claim",
    "data_leak_disclosure",
    "typosquat_domain",
)
ALL_KINDS = ALERT_KINDS + (
    "dark_web_mention",
    "brand_impersonation",
    "attack_surface_issue",
)

TEMPLATE = """\
# Your organisation only. This file stays on your machine and is not shipped.
# Fill in your own names, domains and ABNs. An ABN is checked with the ATO checksum.
organisation: ""
abns: []
domains: []
email_domains: []
brands: []
subsidiaries: []
exclude: []
alert:
  min_confidence: vendor_reported
  kinds:
    - infostealer_credential
    - breach_credential
    - leak_site_claim
    - data_leak_disclosure
    - typosquat_domain
"""

_HOST = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


class WatchlistError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Watchlist:
    """What a premium connector is allowed to see. ABNs are not included."""

    organisation: str
    domains: tuple[str, ...]
    email_domains: tuple[str, ...]
    brands: tuple[str, ...]


@dataclass(frozen=True)
class OrgProfile:
    organisation: str
    abns: tuple[str, ...]
    domains: tuple[str, ...]
    email_domains: tuple[str, ...]
    brands: tuple[str, ...]
    subsidiary_names: tuple[str, ...]
    subsidiary_domains: tuple[str, ...]
    exclude: tuple[str, ...]
    min_confidence: str
    alert_kinds: tuple[str, ...]
    warnings: tuple[str, ...] = ()
    # Registered and business names from ABN Lookup. Vendors are searched by them, so a
    # finding returned under one of them is a finding about this organisation.
    abn_names: tuple[str, ...] = ()

    def vendor_watchlist(self, names: tuple[str, ...] | list[str]) -> Watchlist:
        """Names plus this profile's brands. Excludes and raw ABNs stay local."""
        excluded = {_norm_name(item) for item in self.exclude}
        brands = []
        for name in (*self.brands, *self.subsidiary_names, *names):
            if _norm_name(name) in excluded:
                continue
            brands.append(name)
        return Watchlist(
            organisation=self.organisation,
            domains=self.domains,
            email_domains=self.email_domains,
            brands=tuple(_unique(brands)),
        )

    def narrowed(self, subject: str) -> OrgProfile:
        """Keep only the watchlist entry the user asked about."""
        text = subject.strip()
        domain_hit = _domain_hit(text, self.domains)
        email_hit = _domain_hit(text, self.email_domains)
        brand_hit = _name_hit(text, self.brands)
        subsidiary_hit = _name_hit(text, self.subsidiary_names)
        subsidiary_domain = _domain_hit(text, self.subsidiary_domains)
        abn_hit = ""
        digits = normalise_abn(text)
        if digits and digits in self.abns:
            abn_hit = digits
        if text.startswith("abn:"):
            candidate = text.split(":", 1)[1]
            if candidate in self.abns:
                abn_hit = candidate
        domains: tuple[str, ...] = ()
        if domain_hit:
            domains = (domain_hit,)
        elif subsidiary_domain:
            domains = (subsidiary_domain,)
        extra_domains: tuple[str, ...] = ()
        if subsidiary_domain and not domain_hit:
            extra_domains = (subsidiary_domain,)
        return OrgProfile(
            organisation=self.organisation,
            abns=(abn_hit,) if abn_hit else (),
            domains=domains,
            email_domains=(email_hit,) if email_hit else (),
            brands=(brand_hit,) if brand_hit else (),
            subsidiary_names=(subsidiary_hit,) if subsidiary_hit else (),
            subsidiary_domains=extra_domains,
            exclude=self.exclude,
            min_confidence=self.min_confidence,
            alert_kinds=self.alert_kinds,
            warnings=self.warnings,
            abn_names=self.abn_names,
        )

    def contains(self, subject: str) -> bool:
        text = subject.strip()
        if not text:
            return False
        if text.startswith(("domain:", "email-domain:", "brand:", "abn:", "subsidiary:")):
            return text in self.entry_ids()
        if _domain_hit(text, self._all_domains()):
            return True
        if _name_hit(text, (*self.brands, *self.subsidiary_names)):
            return True
        digits = normalise_abn(text)
        return bool(digits and digits in self.abns)

    def matches(self, subject_type: str, value: str) -> bool:
        if _is_excluded(value, self.exclude):
            return False
        if subject_type in {"domain", "email_domain"}:
            return _domain_hit(value, self._all_domains()) != ""
        if subject_type == "abn":
            digits = normalise_abn(value)
            return bool(digits and digits in self.abns)
        if subject_type == "brand":
            return _name_hit(value, self._all_names()) != ""
        return False

    def canonical(self, subject_type: str, value: str) -> str:
        if subject_type in {"domain", "email_domain"}:
            return _norm_domain(value)
        if subject_type == "abn":
            return normalise_abn(value)
        hit = _name_hit(value, self._all_names())
        return hit or _norm_name(value)

    def entry_id(self, subject_type: str, value: str) -> str:
        canonical = self.canonical(subject_type, value)
        if subject_type == "email_domain":
            return f"email-domain:{canonical}"
        if subject_type == "domain":
            return f"domain:{canonical}"
        if subject_type == "abn":
            return f"abn:{canonical}"
        if _name_hit(value, self.subsidiary_names):
            return "subsidiary:" + _slug(canonical)
        return "brand:" + _slug(canonical)

    def entry_ids(self) -> set[str]:
        found = set()
        for domain in self.domains:
            found.add(self.entry_id("domain", domain))
        for domain in self.email_domains:
            found.add(self.entry_id("email_domain", domain))
        for domain in self.subsidiary_domains:
            found.add(self.entry_id("domain", domain))
        for name in self.brands:
            found.add(self.entry_id("brand", name))
        for name in self.subsidiary_names:
            found.add(self.entry_id("brand", name))
        for abn in self.abns:
            found.add(self.entry_id("abn", abn))
        return found

    def _all_names(self) -> tuple[str, ...]:
        return tuple(_unique((*self.brands, *self.subsidiary_names, *self.abn_names)))

    def _all_domains(self) -> tuple[str, ...]:
        return tuple(_unique((*self.domains, *self.email_domains, *self.subsidiary_domains)))


def init_org_watchlist(path: Path) -> Path:
    """Create an empty user-owned watchlist. Refuses to overwrite."""
    if path.exists():
        raise WatchlistError("exists", "watchlist already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(TEMPLATE, encoding="utf-8")
    return path


def default_watchlist_path() -> Path:
    override = os.environ.get("CYBERAU_ORG_WATCHLIST")
    if override:
        return Path(override)
    return profile_home() / "watchlists" / "org-exposure.yaml"


def load_profile(path: Path, *, routine_path: Path | None = None) -> OrgProfile:
    """Validate the org file, then union domains and brands from the routine list."""
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    if not text.strip():
        raise WatchlistError("empty", "watchlist is empty")
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or not data:
        raise WatchlistError("empty", "watchlist is empty")
    organisation = _optional_str(data.get("organisation"), "organisation")
    abns = _abns(data.get("abns", []))
    domains = _domains(data.get("domains", []), "domains")
    email_domains = _domains(data.get("email_domains", []), "email_domains")
    brands = _names(data.get("brands", []), "brands")
    subsidiary_names, subsidiary_domains = _subsidiaries(data.get("subsidiaries", []))
    exclude = _names(data.get("exclude", []), "exclude")
    # A mail domain may repeat a web domain: they are different entries.
    _reject_duplicates((*domains, *subsidiary_domains))
    _reject_duplicates(email_domains)
    min_confidence, kinds = _alert(data.get("alert"))
    searchable = any((abns, domains, email_domains, brands, subsidiary_names, subsidiary_domains))
    if not organisation or not searchable:
        raise WatchlistError("empty", "watchlist is empty")
    warnings: list[str] = []
    extra_domains, extra_brands, merge_warnings = _routine_lists(routine_path)
    warnings.extend(merge_warnings)
    return OrgProfile(
        organisation=organisation,
        abns=tuple(abns),
        domains=tuple(_unique((*domains, *extra_domains))),
        email_domains=tuple(email_domains),
        brands=tuple(_unique((*brands, *extra_brands))),
        subsidiary_names=tuple(subsidiary_names),
        subsidiary_domains=tuple(subsidiary_domains),
        exclude=tuple(exclude),
        min_confidence=min_confidence,
        alert_kinds=tuple(kinds),
        warnings=tuple(warnings),
    )


def _routine_lists(path: Path | None) -> tuple[list[str], list[str], list[str]]:
    candidate = path
    if candidate is None:
        from cyberau_org_exposure.abn import data_dir

        candidate = data_dir() / "watchlists.yaml"
    if not candidate.is_file():
        return [], [], []
    try:
        data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return [], [], ["routine watchlist could not be read and was skipped"]
    if not isinstance(data, dict):
        return [], [], ["routine watchlist could not be read and was skipped"]
    domains = _soft_domains(data.get("domains"))
    brands = _soft_names(data.get("brands"))
    return domains, brands, []


def _abns(value) -> list[str]:
    items = _string_list(value, "abns")
    digits = []
    for item in items:
        if not checksum_ok(item):
            raise WatchlistError("abn_checksum", "ABN checksum failed")
        digits.append(normalise_abn(item))
    if len(digits) != len(set(digits)):
        raise WatchlistError("abn_checksum", "ABN checksum failed")
    return digits


def _domains(value, field: str) -> list[str]:
    hosts = []
    for item in _string_list(value, field):
        host = _norm_domain(item)
        if not _HOST.fullmatch(host):
            raise WatchlistError("invalid", f"{field} must be host names")
        hosts.append(host)
    return hosts


def _names(value, field: str) -> list[str]:
    names = []
    for item in _string_list(value, field):
        cleaned = re.sub(r"\s+", " ", item).strip()
        if not cleaned or len(cleaned) > 200:
            raise WatchlistError("invalid", f"{field} has an unusable name")
        names.append(cleaned)
    return names


def _subsidiaries(value) -> tuple[list[str], list[str]]:
    if value is None:
        return [], []
    if not isinstance(value, list):
        raise WatchlistError("invalid", "subsidiaries must be a list")
    names: list[str] = []
    domains: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            raise WatchlistError("invalid", "subsidiaries must be a list")
        name = _optional_str(item.get("name"), "subsidiaries.name")
        if not name:
            raise WatchlistError("invalid", "subsidiary name is missing")
        names.append(name)
        domains.extend(_domains(item.get("domains", []), "subsidiaries.domains"))
    return names, domains


def _alert(value) -> tuple[str, list[str]]:
    if value is None:
        return "vendor_reported", list(ALERT_KINDS)
    if not isinstance(value, dict):
        raise WatchlistError("invalid", "alert must be a mapping")
    minimum = value.get("min_confidence", "vendor_reported")
    if minimum not in CONFIDENCE:
        raise WatchlistError("invalid", "alert.min_confidence is not a known level")
    kinds = value.get("kinds", list(ALERT_KINDS))
    if not isinstance(kinds, list) or not kinds:
        raise WatchlistError("invalid", "alert.kinds must be a list")
    cleaned = []
    for kind in kinds:
        if kind not in ALL_KINDS:
            raise WatchlistError("invalid", "alert.kinds has an unknown kind")
        cleaned.append(kind)
    return str(minimum), cleaned


def _reject_duplicates(domains: tuple[str, ...] | list[str]) -> None:
    if len(domains) != len(set(domains)):
        raise WatchlistError("duplicate_domain", "duplicate domain")


def _string_list(value, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise WatchlistError("invalid", f"{field} must be a list")
    items = []
    for item in value:
        if not isinstance(item, str):
            raise WatchlistError("invalid", f"{field} must be a list of strings")
        items.append(item.strip())
    return items


def _optional_str(value, field: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise WatchlistError("invalid", f"{field} must be a string")
    return value.strip()


def _soft_domains(value) -> list[str]:
    if not isinstance(value, list):
        return []
    hosts = []
    for item in value:
        if not isinstance(item, str):
            continue
        host = _norm_domain(item)
        if _HOST.fullmatch(host):
            hosts.append(host)
    return hosts


def _soft_names(value) -> list[str]:
    if not isinstance(value, list):
        return []
    names = []
    for item in value:
        if isinstance(item, str) and item.strip():
            names.append(re.sub(r"\s+", " ", item).strip())
    return names


def _norm_domain(value: str) -> str:
    return value.strip().rstrip(".").lower()


def _norm_name(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().casefold()


def _domain_hit(value: str, domains: tuple[str, ...] | list[str]) -> str:
    host = _norm_domain(value)
    if host.startswith(("domain:", "email-domain:")):
        host = host.split(":", 1)[1]
    for domain in domains:
        if host == domain or host.endswith("." + domain):
            return domain
    return ""


def _name_hit(value: str, names: tuple[str, ...] | list[str]) -> str:
    text = value.strip()
    if text.startswith(("brand:", "subsidiary:")):
        slug = text.split(":", 1)[1]
        for name in names:
            if _slug(name) == slug:
                return name
        return ""
    key = _norm_name(text)
    for name in names:
        if _norm_name(name) == key:
            return name
    return ""


def _is_excluded(value: str, exclude: tuple[str, ...]) -> bool:
    key = _norm_name(value)
    host = _norm_domain(value)
    for item in exclude:
        if _norm_name(item) == key or _norm_domain(item) == host:
            return True
    return False


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")


def _unique(items) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered
