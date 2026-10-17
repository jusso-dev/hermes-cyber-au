"""Read-only UpGuard CyberRisk connector.

Identity breaches, data leak disclosures and typosquat domains. The API key is
sent as the Authorization value with no Bearer prefix. There is no write path:
the disclosure status update is not called.

A typosquat finding uses the watched domain as its subject so the org-exposure
watch can match it. The lookalike hostname is only the source reference.
"""

import hashlib
import json
import os
import re
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

import jsonschema
from cyberau_common import USER_AGENT
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Probe, ToolSpec, register_connector
from cyberau_premium.base import (
    ExposureFinding,
    PremiumConnector,
    Subject,
    Watchlist,
    canonical_finding,
    clamp_to_terms,
    finding_id,
)
from cyberau_premium.caching import cache_for_terms
from cyberau_premium.catalog import get_vendor
from cyberau_premium.present import finding_payload
from cyberau_premium.store import ExposureStore
from pydantic import Field

BASE = "https://cyber-risk.upguard.com/api/public"
BREACHES_URL = f"{BASE}/breaches"
DISCLOSURES_URL = f"{BASE}/dataleaks/disclosures"
TYPOSQUAT_URL = f"{BASE}/typosquat"
TYPOSQUAT_DETAILS_URL = f"{BASE}/typosquat/details"

# No published ceiling. 4 requests per 8 seconds is 30 a minute, then back off on 429.
RATE = 0.5
BURST = 4
SESSION_TTL = 900
TYPOSQUAT_TTL = 12 * 3600
_HOST = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
_TOKEN = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_STATUSES = (
    "Disclosed",
    "Acknowledged",
    "Investigating",
    "Remediating",
    "ClosedNoIssue",
    "ClosedRiskAccepted",
    "ClosedFixedUnverified",
    "ClosedFixedVerified",
)
_Status = Literal[
    "Disclosed",
    "Acknowledged",
    "Investigating",
    "Remediating",
    "ClosedNoIssue",
    "ClosedRiskAccepted",
    "ClosedFixedUnverified",
    "ClosedFixedVerified",
]
_Limit = Annotated[int, Field(ge=1, le=1000)]
_PACKAGE = Path(__file__).resolve().parents[2]
_SCHEMA = _PACKAGE / "schema"
_KIND_SCHEMA = {
    "breaches": "breaches.response.json",
    "disclosures": "disclosures.response.json",
    "typosquat_details": "typosquat_details.response.json",
    "typosquat": "typosquat.response.json",
}
_KIND_FIXTURE = {
    "breaches": "breaches_synthetic.json",
    "disclosures": "disclosures_synthetic.json",
    "typosquat_details": "typosquat_details_synthetic.json",
}
_TRANSPORT = None
_SLEEPER = None
_RESOLVER = None
_SESSION_CACHE = None


def upguard_identity_breaches(limit: _Limit = 100) -> dict:
    """Breached identities for the account's domains. No credential values."""
    problem = _validate_limit(limit)
    if problem:
        return _envelope([], "snapshot", (BREACHES_URL,), (problem,))
    payload, cache, warning = _load_breaches(limit)
    if payload is None:
        return _envelope([], cache, (BREACHES_URL,), (warning,))
    records, _findings = _breach_records(payload, watchlist=None, since=None, limit=limit)
    warnings = (warning,) if warning else ()
    return _envelope(records, cache, (BREACHES_URL,), warnings + _served(cache))


def upguard_data_leaks(
    since: str | None = None,
    until: str | None = None,
    statuses: list[_Status] | None = None,
) -> dict:
    """Data leak disclosures in a time window, with status. No payloads."""
    problem = _validate_leaks(since, until, statuses)
    if problem:
        return _envelope([], "snapshot", (DISCLOSURES_URL,), (problem,))
    params: dict[str, str] = {}
    if since:
        params["min_time"] = since
    if until:
        params["max_time"] = until
    if statuses:
        params["statuses"] = ",".join(statuses)
    payload, cache, warning = _fetch(DISCLOSURES_URL, params, kind="disclosures")
    if warning:
        return _envelope([], cache, (DISCLOSURES_URL,), (warning,))
    records, _findings = _leak_records(
        payload or {},
        watchlist=None,
        since=_parse_time(since) if since else None,
        until=_parse_time(until) if until else None,
        statuses=statuses,
    )
    return _envelope(records, cache, (DISCLOSURES_URL,), _served(cache))


def upguard_typosquats(domain: str) -> dict:
    """Typosquat and lookalike domains for one enabled domain."""
    problem = _validate_domain(domain)
    if problem:
        return _envelope([], "snapshot", (TYPOSQUAT_DETAILS_URL,), (problem,))
    payload, cache, warning = _fetch(
        TYPOSQUAT_DETAILS_URL,
        {"domain": domain},
        kind="typosquat_details",
    )
    if warning:
        return _envelope([], cache, (TYPOSQUAT_DETAILS_URL,), (warning,))
    records = _typosquat_records(payload or {}, domain)
    return _envelope(records, cache, (TYPOSQUAT_DETAILS_URL,), _served(cache))


def connector() -> PremiumConnector:
    spec = get_vendor("upguard")
    return _UpGuardConnector(spec)


class _UpGuardConnector(PremiumConnector):
    def __init__(self, spec) -> None:
        super().__init__(
            key="upguard",
            server_name="upguard",
            attribution=spec.terms.attribution,
            tools=[
                ToolSpec(
                    "upguard_identity_breaches",
                    _described(
                        "Breached identities for the account's domains, with breach name, "
                        "date and data classes. No values."
                    ),
                    upguard_identity_breaches,
                ),
                ToolSpec(
                    "upguard_data_leaks",
                    _described("Data leak disclosures in a time window, with status."),
                    upguard_data_leaks,
                ),
                ToolSpec(
                    "upguard_typosquats",
                    _described("Typosquat and lookalike domains for one enabled domain."),
                    upguard_typosquats,
                ),
            ],
            vendor=spec.server,
            licence_env=tuple(spec.licence_env),
            terms=spec.terms,
            quota=spec.quota,
        )

    def exposure_for(self, watchlist: Watchlist, since: date) -> list[ExposureFinding]:
        if not _offline() and lookup("UPGUARD_API_KEY") is None:
            raise ValueError("UPGUARD_API_KEY is not set")
        findings: list[ExposureFinding] = []
        payload, _cache, warning = _load_breaches(1000)
        if payload is None:
            raise ValueError(warning or "UpGuard breach payload was not usable")
        _records, breach_findings = _breach_records(
            payload or {},
            watchlist=watchlist,
            since=since,
            limit=1000,
        )
        findings.extend(breach_findings)
        leak_payload, _cache, warning = _fetch(DISCLOSURES_URL, {}, kind="disclosures")
        if warning:
            raise ValueError(warning)
        _rows, leak_findings = _leak_records(
            leak_payload or {},
            watchlist=watchlist,
            since=datetime(since.year, since.month, since.day, tzinfo=UTC),
            until=None,
            statuses=None,
        )
        findings.extend(leak_findings)
        for watched in _watch_domains(watchlist):
            detail, _cache, warning = _fetch(
                TYPOSQUAT_DETAILS_URL,
                {"domain": watched},
                kind="typosquat_details",
            )
            if warning and (
                "UPGUARD_API_KEY" in warning or warning.startswith("UpGuard schema drift")
            ):
                raise ValueError(warning)
            if warning or detail is None:
                continue
            findings.extend(_typosquat_findings(detail, watched, since=since))
        _persist(findings, watchlist)
        return findings

    def health(self, *, live: bool = False, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            problem = bundled_schema_problems()
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        result = self.health_result(live=False)
        if not live:
            return Probe(self.key, result.ok, result.detail)
        if not result.configured:
            return Probe(self.key, False, "UPGUARD_API_KEY is not set, no live check was made")
        payload, cache, warning = _fetch(TYPOSQUAT_URL, {}, kind="typosquat", force_live=True)
        if warning:
            return Probe(self.key, False, warning)
        if cache != "miss":
            return Probe(self.key, False, f"live check was answered from a {cache} copy")
        problem = schema_problem("typosquat.response.json", payload or {})
        if problem:
            return Probe(self.key, False, problem)
        return Probe(self.key, True, "live ok")


def schema_problem(schema_name: str, payload: dict) -> str | None:
    schema = json.loads((_SCHEMA / schema_name).read_text(encoding="utf-8"))
    try:
        jsonschema.Draft202012Validator(schema).validate(payload)
    except jsonschema.ValidationError as exc:
        detail = exc.message.split("\n", 1)[0]
        return f"UpGuard schema drift, {detail}"
    return None


def bundled_schema_problems() -> str | None:
    pairs = (
        ("breaches.response.json", "breaches_synthetic.json"),
        ("disclosures.response.json", "disclosures_synthetic.json"),
        ("typosquat_details.response.json", "typosquat_details_synthetic.json"),
    )
    for schema_name, fixture_name in pairs:
        problem = schema_problem(schema_name, _read_json(_fixture_path(fixture_name)))
        if problem:
            return problem
    extra = os.environ.get("CYBERAU_UPGUARD_SCHEMA_FIXTURE")
    if extra:
        return schema_problem("breaches.response.json", _read_json(Path(extra)))
    return None


def _described(text: str) -> str:
    return f"{text} {_attribution()}"


def _attribution() -> str:
    return get_vendor("upguard").terms.attribution


def _envelope(data, cache: str, urls: tuple[str, ...], warnings: tuple[str, ...] = ()) -> dict:
    return envelope(
        "upguard",
        data,
        urls=list(urls),
        cache=cache,
        warnings=tuple(_scrub(item) for item in warnings),
        attribution=_attribution(),
    )


def _served(cache: str) -> tuple[str, ...]:
    """Say so when a result is not a live answer."""
    if cache == "snapshot":
        return ("Bundled synthetic snapshot, not live UpGuard data.",)
    if cache == "stale":
        return ("UpGuard could not be reached. This is an older cached copy.",)
    return ()


def _validate_limit(limit: int) -> str:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
        return "limit must be between 1 and 1000"
    return ""


def _validate_domain(domain: str) -> str:
    if not isinstance(domain, str) or _HOST.fullmatch(domain) is None:
        return "domain must be a hostname"
    return ""


def _validate_leaks(since: str | None, until: str | None, statuses: list[str] | None) -> str:
    if since and _parse_time(since) is None:
        return "since must be a date-time"
    if until and _parse_time(until) is None:
        return "until must be a date-time"
    if statuses:
        unknown = [item for item in statuses if item not in _STATUSES]
        if unknown:
            return "statuses must be UpGuard disclosure statuses"
    return ""


def _load_breaches(limit: int) -> tuple[dict | None, str, str]:
    params = {
        "page_size": str(min(1000, max(10, limit))),
        "sort_by": "date_last_breach",
        "sort_desc": "true",
    }
    if _offline():
        return _fetch(BREACHES_URL, params, kind="breaches")
    identities: list[dict] = []
    breaches: list[dict] = []
    cache = "snapshot"
    pages = 0
    payload: dict = {}
    max_pages = get_vendor("upguard").max_pages
    while pages < max_pages:
        payload, cache, warning = _fetch(BREACHES_URL, params, kind="breaches")
        if warning and payload is None:
            return None, cache, warning
        if payload is None:
            return None, cache, warning or "UpGuard breach payload was not usable"
        identities.extend(payload.get("breached_identities") or [])
        breaches.extend(payload.get("breaches") or [])
        pages += 1
        token = payload.get("next_page_token")
        if not token or len(identities) >= limit:
            break
        params = {**params, "page_token": str(token)}
    notice = ""
    if pages >= max_pages and payload.get("next_page_token") and len(identities) < limit:
        notice = "UpGuard results were truncated at the page cap."
    return {"breached_identities": identities, "breaches": breaches}, cache, notice


def _fetch(
    url: str,
    params: dict,
    *,
    kind: str,
    force_live: bool = False,
) -> tuple[dict | None, str, str]:
    offline = _offline() and not force_live
    if offline:
        fixture = _KIND_FIXTURE.get(kind)
        if fixture is None:
            return None, "snapshot", "no offline snapshot for this UpGuard call"
        return _read_json(_fixture_path(fixture)), "snapshot", ""
    if lookup("UPGUARD_API_KEY") is None:
        return None, "snapshot", "UPGUARD_API_KEY is not set"
    directory = _data_dir()
    disk = kind in {"typosquat", "typosquat_details"}
    cache = _ttl_cache(directory) if disk else _session_cache(directory)
    scope = _scope()
    cache_key = cache.key("GET", url, params, b"", scope)
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    kwargs = {"resolver": _RESOLVER} if _RESOLVER is not None else {}
    client = HttpClient(
        "upguard",
        policy=EgressPolicy(allowlist, "upguard", **kwargs),
        cache=cache,
        limiter=RateLimiter(directory / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=RATE,
        burst=BURST,
        window="rolling",
        auth_scope=scope,
        transport=_TRANSPORT,
        sleeper=_SLEEPER,
        retries=1,
    )
    ttl = TYPOSQUAT_TTL if disk else SESSION_TTL
    try:
        try:
            response = client.get(
                url,
                params=params or None,
                headers={"Authorization": lookup("UPGUARD_API_KEY") or ""},
                ttl=ttl,
                skip_cache=force_live,
            )
        except EgressDenied as exc:
            return None, "snapshot", _scrub(str(exc))
        except (HttpError, TimeoutError) as exc:
            # A live probe must never be answered from a cached copy.
            cached = None if force_live else cache.get(cache_key)
            old = _load_body(cached.body) if cached is not None else None
            if old is not None and schema_problem(_KIND_SCHEMA[kind], old) is None:
                return old, "stale", ""
            return None, "snapshot", _scrub(str(exc))
    finally:
        client.close()
    if response.status in (401, 403):
        return (
            None,
            "snapshot",
            (
                f"UpGuard returned HTTP {response.status}. "
                "Check UPGUARD_API_KEY and its read permissions."
            ),
        )
    if response.status == 404:
        return None, "snapshot", "UpGuard has not enabled typosquat monitoring for this domain."
    if response.status == 429:
        return None, "snapshot", "UpGuard rate limit reached. Back off and retry."
    if response.status >= 400:
        return None, "snapshot", f"UpGuard returned HTTP {response.status}."
    payload = _load_body(response.body)
    if payload is None:
        return None, response.cache, "UpGuard response was not usable"
    problem = schema_problem(_KIND_SCHEMA[kind], payload)
    if problem:
        return None, response.cache, problem
    return payload, response.cache, ""


def _breach_records(
    payload: dict,
    *,
    watchlist: Watchlist | None,
    since: date | None,
    limit: int,
) -> tuple[list[dict], list[ExposureFinding]]:
    catalogue = {str(item.get("id")): item for item in payload.get("breaches") or []}
    grouped: dict[tuple[str, str], dict] = {}
    for identity in payload.get("breached_identities") or []:
        domain = str(identity.get("domain") or "").strip().rstrip(".")
        if _HOST.fullmatch(domain) is None:
            continue
        when = str(identity.get("last_breach_date") or "")
        for breach_id in identity.get("breach_ids") or []:
            key = (domain.casefold(), str(breach_id))
            slot = grouped.setdefault(
                key,
                {"domain": domain, "breach_id": str(breach_id), "when": when, "identities": 0},
            )
            slot["identities"] += 1
            if when > slot["when"]:
                slot["when"] = when
    rows = sorted(grouped.values(), key=lambda item: item["when"], reverse=True)
    records: list[dict] = []
    findings: list[ExposureFinding] = []
    domains = _watch_domains(watchlist) if watchlist is not None else None
    for slot in rows:
        if len(records) >= limit:
            break
        observed = _parse_time(slot["when"])
        if observed is None:
            continue
        if since is not None and observed.astimezone(UTC).date() < since:
            continue
        subject = slot["domain"]
        if domains is not None:
            matched = _match_domain(subject, domains)
            if matched is None:
                continue
            subject = matched
        breach = catalogue.get(slot["breach_id"]) or {}
        classes = [str(item) for item in breach.get("exposed_data_classes") or [] if item]
        title = str(breach.get("title") or breach.get("name") or slot["breach_id"])
        source_ref = f"{subject}:{slot['breach_id']}"
        finding = _finding(
            kind="breach_credential",
            subject_value=subject,
            source_ref=source_ref,
            observed=observed,
            data_classes=classes or None,
            counts={"identities": slot["identities"]},
        )
        findings.append(finding)
        records.append(
            {
                "domain": subject,
                "breach_id": _plain(slot["breach_id"]),
                "breach_name": _text(title),
                "breach_date": observed.isoformat(),
                "data_classes": [_text(item) for item in classes],
                "identities": slot["identities"],
                "finding": finding_payload(finding),
            }
        )
    return records, findings


def _leak_records(
    payload: dict,
    *,
    watchlist: Watchlist | None,
    since: datetime | None,
    until: datetime | None,
    statuses: list[str] | None,
) -> tuple[list[dict], list[ExposureFinding]]:
    records: list[dict] = []
    findings: list[ExposureFinding] = []
    domains = _watch_domains(watchlist) if watchlist is not None else None
    allowed = set(statuses or [])
    for item in payload.get("disclosures") or []:
        status = str(item.get("status") or "")
        if allowed and status not in allowed:
            continue
        observed = _parse_time(str(item.get("date_disclosed") or ""))
        if observed is None:
            continue
        if since is not None and observed < since:
            continue
        if until is not None and observed > until:
            continue
        host = _host_of(str(item.get("url") or ""))
        subject = host
        if domains is not None:
            if not host:
                continue
            matched = _match_domain(host, domains)
            if matched is None:
                continue
            subject = matched
        severity = item.get("severity")
        counts = {"severity": int(severity)} if isinstance(severity, int) else None
        source_ref = str(item.get("id"))
        finding = None
        if subject:
            finding = _finding(
                kind="data_leak_disclosure",
                subject_value=subject,
                source_ref=source_ref,
                observed=observed,
                counts=counts,
            )
            if domains is not None:
                findings.append(finding)
        record = {
            "id": _plain(source_ref),
            "status": status if status in _STATUSES else _text(status),
            "date_disclosed": observed.isoformat(),
            "host": _text(host),
            "watched_domain": subject if domains is not None else None,
            "description": _text(str(item.get("description") or "")),
        }
        if isinstance(severity, int):
            record["severity"] = severity
        implication = str(item.get("implication") or "")
        if implication:
            record["implication"] = _text(implication)
        if finding is not None:
            record["finding"] = finding_payload(finding)
        records.append(record)
    return records, findings


def _typosquat_rows(payload: dict):
    for state in ("registered", "ignored", "unregistered"):
        for item in payload.get(state) or []:
            hostname = str(item.get("hostname") or "").strip().rstrip(".")
            if hostname:
                observed = _parse_time(str(item.get("date_detected") or ""))
                yield state, hostname, item, observed


def _typosquat_records(payload: dict, watched: str) -> list[dict]:
    records = []
    for state, hostname, item, observed in _typosquat_rows(payload):
        mx = item.get("mx_records") or []
        record = {
            "watched_domain": watched,
            "hostname": _text(hostname),
            "state": state,
            "registered": state != "unregistered",
            "date_detected": observed.isoformat() if observed else None,
            "has_mx": bool(mx),
        }
        permutation = str(item.get("permutation_type") or "")
        if permutation:
            record["permutation_type"] = _text(permutation)
        if observed is not None and state != "unregistered":
            finding = _typosquat_finding(watched, hostname, observed, bool(mx), state)
            record["finding"] = finding_payload(finding)
        records.append(record)
    return records


def _typosquat_findings(payload: dict, watched: str, *, since: date) -> list[ExposureFinding]:
    findings = []
    for state, hostname, item, observed in _typosquat_rows(payload):
        if state == "unregistered" or observed is None:
            continue
        if observed.astimezone(UTC).date() < since:
            continue
        findings.append(
            _typosquat_finding(watched, hostname, observed, bool(item.get("mx_records")), state)
        )
    return findings


def _typosquat_finding(
    watched: str,
    hostname: str,
    observed: datetime,
    has_mx: bool,
    state: str,
) -> ExposureFinding:
    counts = {"registered": 1}
    if has_mx:
        counts["mx"] = 1
    if state == "ignored":
        counts["ignored"] = 1
    return _finding(
        kind="typosquat_domain",
        subject_value=watched,
        source_ref=hostname,
        observed=observed,
        counts=counts,
    )


def _finding(
    *,
    kind: str,
    subject_value: str,
    source_ref: str,
    observed: datetime,
    data_classes: list[str] | None = None,
    counts: dict[str, int] | None = None,
) -> ExposureFinding:
    terms = get_vendor("upguard").terms
    finding = ExposureFinding(
        finding_id=finding_id("upguard", kind, subject_value, source_ref),
        vendor="upguard",
        kind=kind,
        subject=Subject(type="domain", value=subject_value, watchlist_entry=subject_value),
        observed_at=observed,
        first_seen=observed,
        licence_scope="store_metadata",
        confidence="vendor_reported",
        counts=counts,
        data_classes=data_classes,
        source_ref=source_ref,
        stix_exportable=False,
        contains_personal_information=False,
    )
    return clamp_to_terms(canonical_finding(finding), terms)


def _persist(findings: list[ExposureFinding], watchlist: Watchlist) -> None:
    if not findings or not os.environ.get("CYBERAU_DATA_DIR"):
        return
    store = ExposureStore(Path(os.environ["CYBERAU_DATA_DIR"]) / "intel.sqlite")
    terms = get_vendor("upguard").terms
    for finding in findings:
        store.write(finding, terms=terms, watchlist=watchlist)


def _watch_domains(watchlist: Watchlist) -> list[str]:
    values = list(watchlist.domains) + list(watchlist.email_domains)
    for item in watchlist.subsidiaries:
        for domain in item.get("domains") or []:
            if isinstance(domain, str):
                values.append(domain)
    excluded = {item.casefold() for item in watchlist.exclude}
    found: list[str] = []
    seen: set[str] = set()
    for value in values:
        key = value.strip().rstrip(".").casefold()
        if not key or key in seen or key in excluded:
            continue
        seen.add(key)
        found.append(value.strip().rstrip("."))
    return found


def _match_domain(host: str, domains: list[str]) -> str | None:
    folded = host.strip().rstrip(".").casefold()
    found = []
    for candidate in domains:
        target = candidate.strip().rstrip(".").casefold()
        if folded == target or folded.endswith("." + target):
            found.append(candidate)
    if not found:
        return None
    return max(found, key=lambda item: len(item.casefold()))


def _host_of(url: str) -> str:
    if not url:
        return ""
    host = urlsplit(url).hostname or ""
    return host.rstrip(".").lower()


def _plain(value: str) -> str:
    """Keep an opaque feed identifier as is when it is plain, otherwise wrap it."""
    return value if _TOKEN.fullmatch(value) else _text(value)


def _text(value: str) -> str:
    if not value.strip():
        return ""
    return untrusted_text(value, "upguard")


def _parse_time(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _offline() -> bool:
    return os.environ.get("CYBERAU_OFFLINE") == "1"


def _data_dir() -> Path:
    return Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-upguard"))


def _scope() -> str:
    secret = lookup("UPGUARD_API_KEY") or ""
    return hashlib.sha256(secret.encode()).hexdigest()[:16]


def _scrub(message: str) -> str:
    cleaned = redact(message)
    secret = lookup("UPGUARD_API_KEY")
    if secret:
        cleaned = cleaned.replace(secret, "[REDACTED]")
    return cleaned


def _session_cache(directory: Path):
    global _SESSION_CACHE
    path = directory / "upguard-session.sqlite"
    terms = get_vendor("upguard").terms.model_copy(
        update={"cache": "session", "cache_ttl_max_s": 0}
    )
    if _SESSION_CACHE is None or _SESSION_CACHE.path != path:
        _SESSION_CACHE = cache_for_terms(path, terms)
    return _SESSION_CACHE


def _ttl_cache(directory: Path):
    terms = get_vendor("upguard").terms
    return cache_for_terms(directory / "upguard-ttl.sqlite", terms)


def _fixture_path(name: str) -> Path:
    override = os.environ.get("CYBERAU_UPGUARD_FIXTURES")
    root = Path(override) if override else _PACKAGE / "tests" / "fixtures"
    return root / name


def _read_json(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name} is not a JSON object")
    return payload


def _load_body(body: bytes) -> dict | None:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _allowlist() -> Path:
    return _PACKAGE.parent / "egress-allowlist.yaml"


register_connector("upguard", connector)
