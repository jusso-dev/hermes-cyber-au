"""Read-only Hudson Rock Cavalier connector.

Counts and overview statistics only. Passwords, cookies and other credential
values are dropped before a result, a session cache or the exposures table.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import random
import re
from datetime import UTC, date, datetime, time
from pathlib import Path
from zoneinfo import ZoneInfo

import httpx
import jsonschema
import yaml
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimited, RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Probe, ToolSpec, register_connector
from cyberau_common.snapshot import unavailable
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
from cyberau_premium.paths import data_dir
from cyberau_premium.present import finding_payload
from cyberau_premium.store import ExposureStore

SEARCH_URL = "https://api.hudsonrock.com/json/v3/search-by-domain"
OVERVIEW_URL = "https://api.hudsonrock.com/json/v3/search-by-domain/overview"
KEY_ENV = "HUDSONROCK_API_KEY"
VENDOR = "hudsonrock"
# Documented ceiling: 50 requests per 10 seconds. Stay under it.
RATE_PER_SECOND = 4
BURST = 40
TIMEOUT_SECONDS = 90
SYDNEY = ZoneInfo("Australia/Sydney")
_PACKAGE = Path(__file__).resolve().parents[2]
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_COUNT_KEYS = ("employees", "users", "third_parties")
_CRED_BUCKET = {
    "employee": "employees",
    "user": "users",
    "third_party": "third_parties",
}
_OVERVIEW_TIMES = (
    "last_employee_compromised",
    "last_user_compromised",
    "last_employee_uploaded",
    "last_user_uploaded",
)
_UNAVAILABLE = "Hudson Rock could not be reached and there is no cached copy."
_UNUSABLE = "Hudson Rock payload was not usable."
_SNAPSHOT = "Served from the operator-supplied snapshot file, not a live Hudson Rock fetch."
_SERVED_STALE = "Served from the session cache copy. This is not a live Hudson Rock result."
_LIVE_STATES = ("miss", "hit")
_EXPOSURE = "Hudson Rock domain exposure"
_OVERVIEW = "Hudson Rock domain overview"

_TRANSPORT = None
_SLEEPER = None
_RESOLVER = None
_RNG = None
_SESSION_CACHE: HttpCache | None = None


def reset_client_state() -> None:
    """Drop process-local hooks and the session cache. Tests call this."""
    global _SESSION_CACHE, _TRANSPORT, _SLEEPER, _RESOLVER, _RNG
    if _SESSION_CACHE is not None:
        _SESSION_CACHE.clear_session()
    _SESSION_CACHE = None
    _TRANSPORT = None
    _SLEEPER = None
    _RESOLVER = None
    _RNG = None


def schema_fixture_dir() -> Path:
    """Copies for the offline schema check only. Never served as Hudson Rock data."""
    return _PACKAGE / "tests" / "fixtures"


def hudsonrock_domain_exposure(
    domains: list[str],
    types: list[str] | None = None,
    since: str | None = None,
) -> dict:
    """Counts for watchlist domains. Never returns passwords or cookies."""
    cleaned, problem = _clean_domains(domains)
    if problem:
        return _envelope([], "snapshot", (problem,))
    selected, problem = _clean_types(types)
    if problem:
        return _envelope([], "snapshot", (problem,))
    since_text, problem = _clean_since(since)
    if problem:
        return _envelope([], "snapshot", (problem,))
    if lookup(KEY_ENV) is None:
        return _envelope([], "snapshot", (unavailable(_EXPOSURE, f"{KEY_ENV} is not set"),))
    watchlist, problem = _load_watchlist()
    if problem or watchlist is None:
        return _envelope([], "snapshot", (problem,))
    rejected = _outside_watchlist(cleaned, watchlist)
    if rejected:
        names = ", ".join(rejected)
        return _envelope(
            [],
            "snapshot",
            (f"These domains are outside the org-exposure watchlist: {names}.",),
        )
    payload, cache, warning = _collect(
        SEARCH_URL,
        _search_body(cleaned, selected, since_text),
    )
    if payload is None:
        # No live, cached or operator-supplied data. Never fall back to fixtures.
        state = cache if cache == "stale" else "snapshot"
        return _envelope([], state, (unavailable(_EXPOSURE, warning),))
    findings, build_warning = _search_findings(payload, cleaned, selected, since_text)
    warning = warning or build_warning
    if build_warning and not findings:
        return _envelope([], "snapshot", (build_warning,))
    if cache in _LIVE_STATES:
        _remember(findings, watchlist)
    return _envelope(
        [finding_payload(item) for item in findings],
        cache,
        (warning,) if warning else (),
        urls=[SEARCH_URL],
        data_as_of=_latest(findings),
    )


def hudsonrock_domain_overview(domain: str) -> dict:
    """Overview statistics for one watchlist domain."""
    cleaned = _clean_domain(domain) if isinstance(domain, str) else None
    if cleaned is None:
        return _envelope([], "snapshot", ("domain must be a fully qualified domain name.",))
    if lookup(KEY_ENV) is None:
        return _envelope([], "snapshot", (unavailable(_OVERVIEW, f"{KEY_ENV} is not set"),))
    watchlist, problem = _load_watchlist()
    if problem or watchlist is None:
        return _envelope([], "snapshot", (problem,))
    rejected = _outside_watchlist([cleaned], watchlist)
    if rejected:
        return _envelope(
            [],
            "snapshot",
            (f"These domains are outside the org-exposure watchlist: {cleaned}.",),
        )
    payload, cache, warning = _collect(OVERVIEW_URL, {"domains": [cleaned]})
    if payload is None:
        state = cache if cache == "stale" else "snapshot"
        return _envelope([], state, (unavailable(_OVERVIEW, warning),))
    findings, build_warning = _overview_findings(payload, cleaned)
    warning = warning or build_warning
    if build_warning and not findings:
        return _envelope([], "snapshot", (build_warning,))
    if cache in _LIVE_STATES:
        _remember(findings, watchlist)
    return _envelope(
        [finding_payload(item) for item in findings],
        cache,
        (warning,) if warning else (),
        urls=[OVERVIEW_URL],
        data_as_of=_latest(findings),
    )


def connector() -> PremiumConnector:
    spec = get_vendor(VENDOR)
    terms = spec.terms.attribution
    return _HudsonRock(
        attribution=terms,
        exposure=(
            "Counts of compromised employees, users and third parties for watchlist "
            "domains, with first and last compromise dates. Never returns passwords "
            f"or cookies. Terms: {terms}"
        ),
        overview=f"Vendor overview statistics for one watchlist domain. Terms: {terms}",
    )


class _HudsonRock(PremiumConnector):
    def __init__(self, *, attribution: str, exposure: str, overview: str) -> None:
        spec = get_vendor(VENDOR)
        super().__init__(
            key="hudson-rock",
            server_name=VENDOR,
            attribution=attribution,
            tools=[
                ToolSpec("hudsonrock_domain_exposure", exposure, hudsonrock_domain_exposure),
                ToolSpec("hudsonrock_domain_overview", overview, hudsonrock_domain_overview),
            ],
            vendor=spec.server,
            licence_env=tuple(spec.licence_env),
            terms=spec.terms,
            quota=spec.quota,
        )

    def exposure_for(self, watchlist: Watchlist, since: date) -> list[ExposureFinding]:
        if lookup(KEY_ENV) is None:
            raise RuntimeError(f"{KEY_ENV} is not set.")
        domains = []
        for value in sorted(watchlist.known_subjects()):
            cleaned = _clean_domain(value)
            if cleaned:
                domains.append(cleaned)
        if not domains:
            return []
        since_text = since.isoformat()
        payload, cache, warning = _collect(
            SEARCH_URL,
            _search_body(domains, None, since_text),
        )
        if payload is None:
            raise RuntimeError(warning or _UNAVAILABLE)
        if cache == "snapshot":
            # Findings carry no warning. A snapshot must not pass as live exposure.
            raise RuntimeError(_SNAPSHOT)
        findings, build_warning = _search_findings(payload, domains, None, since_text)
        if build_warning and not findings:
            raise RuntimeError(build_warning)
        if cache in _LIVE_STATES:
            _remember(findings, watchlist)
        return findings

    def health(self, *, live: bool = False, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            return self._schema_probe()
        configured = self.health_result(live=False)
        if not configured.configured:
            if live:
                return Probe(self.key, False, f"{KEY_ENV} is not set")
            return Probe(self.key, configured.ok, configured.detail)
        if not live:
            return Probe(self.key, True, "offline ok")
        if os.environ.get("CYBERAU_OFFLINE") == "1":
            return Probe(self.key, False, "offline: the live probe was not run")
        domain = _probe_domain()
        if domain is None:
            return Probe(self.key, False, "no org-exposure watchlist domain for the live probe")
        raw, _cache, warning = _transport_json(OVERVIEW_URL, {"domains": [domain]})
        if warning or raw is None:
            return Probe(self.key, False, warning or "live probe failed")
        problem = _schema_problem(OVERVIEW_URL, raw)
        if problem:
            return Probe(self.key, False, problem)
        return Probe(self.key, True, "live ok")

    def _schema_probe(self) -> Probe:
        try:
            search = _read_json(schema_fixture_dir() / "search_by_domain_synthetic.json")
            overview = _read_json(schema_fixture_dir() / "overview_synthetic.json")
        except (OSError, json.JSONDecodeError, TypeError):
            return Probe(self.key, False, "schema drift: fixture could not be read")
        problems = []
        for label, url, payload in (
            ("search-by-domain", SEARCH_URL, search),
            ("overview", OVERVIEW_URL, overview),
        ):
            problem = _schema_problem(url, payload)
            if problem:
                detail = problem.removeprefix("schema drift: ")
                problems.append(f"{label}: {detail}")
        if problems:
            return Probe(self.key, False, "schema drift: " + "; ".join(problems))
        return Probe(self.key, True, "schema ok")


def _envelope(
    data,
    cache: str,
    warnings: tuple[str, ...] = (),
    *,
    urls: list[str] | None = None,
    data_as_of: str | None = None,
) -> dict:
    return envelope(
        VENDOR,
        data,
        urls=urls or [],
        cache=cache,
        data_as_of=data_as_of,
        warnings=warnings,
        attribution=get_vendor(VENDOR).terms.attribution,
    )


def _clean_domain(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().lower().rstrip(".")
    if not text or "." not in text or len(text) > 253:
        return None
    try:
        ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        return None
    if any(_LABEL.fullmatch(label) is None for label in text.split(".")):
        return None
    return text


def _clean_domains(values: object) -> tuple[list[str], str]:
    if not isinstance(values, list) or not values:
        return [], "domains must name at least one fully qualified domain."
    if len(values) > 50:
        return [], "domains accepts at most 50 names."
    cleaned: list[str] = []
    for value in values:
        domain = _clean_domain(value)
        if domain is None:
            return [], "domains must be fully qualified domain names."
        if domain not in cleaned:
            cleaned.append(domain)
    return cleaned, ""


def _clean_types(values: object) -> tuple[list[str] | None, str]:
    if values is None:
        return None, ""
    if not isinstance(values, list):
        return None, "types must be a list."
    cleaned: list[str] = []
    for value in values:
        if value not in _COUNT_KEYS:
            return None, "types must be employees, users or third_parties."
        if value not in cleaned:
            cleaned.append(value)
    return cleaned, ""


def _clean_since(value: object) -> tuple[str | None, str]:
    if value is None:
        return None, ""
    if not isinstance(value, str) or _DATE.fullmatch(value) is None:
        return None, "since must be YYYY-MM-DD in Australia/Sydney."
    try:
        date.fromisoformat(value)
    except ValueError:
        return None, "since must be YYYY-MM-DD in Australia/Sydney."
    return value, ""


def _watchlist_path() -> Path:
    override = os.environ.get("CYBERAU_ORG_WATCHLIST")
    if override:
        return Path(override)
    raw = os.environ.get("CYBERAU_DATA_DIR")
    if raw:
        return Path(raw).resolve().parent.parent / "watchlists" / "org-exposure.yaml"
    return Path("watchlists") / "org-exposure.yaml"


def _load_watchlist() -> tuple[Watchlist | None, str]:
    path = _watchlist_path()
    if not path.is_file():
        return Watchlist(), ""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return None, "The org-exposure watchlist could not be read."
    if not isinstance(raw, dict):
        return None, "The org-exposure watchlist could not be read."
    try:
        return Watchlist.model_validate(raw), ""
    except ValueError:
        return None, "The org-exposure watchlist could not be read."


def _allow_external() -> bool:
    raw = os.environ.get("CYBERAU_CONFIG")
    if not raw:
        return False
    try:
        config = yaml.safe_load(Path(raw).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return False
    if not isinstance(config, dict):
        return False
    premium = (config.get("cyber_au") or {}).get("premium") or {}
    block = premium.get(VENDOR) if isinstance(premium, dict) else None
    return isinstance(block, dict) and block.get("allow_external") is True


def _outside_watchlist(domains: list[str], watchlist: Watchlist) -> list[str]:
    if _allow_external():
        return []
    known = watchlist.known_subjects()
    return [domain for domain in domains if domain.casefold() not in known]


def _probe_domain() -> str | None:
    watchlist, problem = _load_watchlist()
    if problem or watchlist is None:
        return None
    for value in sorted(watchlist.known_subjects()):
        cleaned = _clean_domain(value)
        if cleaned:
            return cleaned
    return None


def _search_body(
    domains: list[str],
    types: list[str] | None,
    since: str | None,
) -> dict:
    body: dict = {"domains": domains, "filter_credentials": True}
    if types:
        body["types"] = types
    if since:
        start = datetime.combine(date.fromisoformat(since), time.min, tzinfo=SYDNEY)
        body["start_date"] = start.isoformat()
    return body


def _collect(url: str, body: dict, *, force_live: bool = False) -> tuple[dict | None, str, str]:
    spec = get_vendor(VENDOR)
    cursor = None
    seen: set[str] = set()
    rows: list = []
    state = "miss"
    warning = ""
    for _page in range(spec.max_pages):
        page = dict(body)
        if cursor:
            page["cursor"] = cursor
        payload, state, warning = _load_page(url, page, force_live=force_live and cursor is None)
        if payload is None:
            if rows:
                return {"data": rows, "nextCursor": None}, state, warning or _UNAVAILABLE
            return None, state, warning
        rows.extend(payload.get("data") or [])
        if state == "snapshot":
            cursor = None
            break
        nxt = payload.get("nextCursor")
        if not isinstance(nxt, str) or not nxt or nxt in seen:
            cursor = None
            break
        seen.add(nxt)
        cursor = nxt
    if cursor:
        warning = f"Hudson Rock paging stopped at {spec.max_pages} pages."
    return {"data": rows, "nextCursor": None}, state, warning


def _load_page(url: str, body: dict, *, force_live: bool) -> tuple[dict | None, str, str]:
    if not force_live:
        snapshot, problem = _read_snapshot(url)
        if problem:
            return None, "snapshot", problem
        if snapshot is not None:
            accepted, problem = _accept(url, snapshot)
            if problem:
                return None, "snapshot", problem
            return accepted, "snapshot", _SNAPSHOT
    secret = lookup(KEY_ENV)
    if secret is None:
        return None, "snapshot", f"{KEY_ENV} is not set."
    session = _session_cache()
    cache_key = session.key("POST", url, None, _body_bytes(body), _scope(secret))
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    cached = session.get(cache_key)
    if cached and not force_live and (offline or session.fresh(cached)):
        payload = _load_cached(cached.body)
        if payload is not None:
            if offline:
                return payload, "stale", _SERVED_STALE
            return payload, "hit", ""
    if offline:
        return None, "snapshot", _UNAVAILABLE
    try:
        status, headers, raw = _http(url, body)
    except (EgressDenied, HttpError, httpx.HTTPError, RateLimited, TimeoutError) as exc:
        return _from_cache_or_warning(cached, _safe(str(exc)) or _UNAVAILABLE)
    if status in (401, 403):
        return (
            None,
            "snapshot",
            (
                f"Hudson Rock refused the request (HTTP {status}). "
                f"Set {KEY_ENV} to your paid Cavalier licence key."
            ),
        )
    if status == 429:
        retry = headers.get("retry-after", "").strip()
        # The header is vendor text. Echo it only as a short whole number.
        extra = f" Retry after {retry} seconds." if retry.isdigit() and len(retry) <= 5 else ""
        return None, "snapshot", f"Hudson Rock rate limit (HTTP 429).{extra}"
    if status == 408 or status >= 500:
        message = (
            f"Hudson Rock timed out (HTTP {status}) and no cached result is available."
            if status == 408
            else f"Hudson Rock returned HTTP {status} and no cached result is available."
        )
        return _from_cache_or_warning(cached, message)
    if status >= 400:
        return None, "snapshot", f"Hudson Rock returned HTTP {status}."
    accepted, problem = _accept(url, raw)
    if problem:
        return None, "snapshot", problem
    session.put(
        cache_key,
        status=200,
        headers={},
        body=_body_bytes(accepted),
        ttl=3600,
    )
    return accepted, "miss", ""


def _from_cache_or_warning(cached, message: str) -> tuple[dict | None, str, str]:
    if cached is not None:
        payload = _load_cached(cached.body)
        if payload is not None:
            return payload, "stale", _SERVED_STALE
    return None, "snapshot", message


def _transport_json(url: str, body: dict) -> tuple[dict | None, str, str]:
    """Live probe path. Returns the raw JSON object, before stripping."""
    secret = lookup(KEY_ENV)
    if secret is None:
        return None, "snapshot", f"{KEY_ENV} is not set."
    try:
        status, _headers, raw = _http(url, body)
    except (EgressDenied, HttpError, httpx.HTTPError, RateLimited, TimeoutError) as exc:
        return None, "snapshot", _safe(str(exc)) or _UNAVAILABLE
    if status in (401, 403):
        return (
            None,
            "snapshot",
            (
                f"Hudson Rock refused the request (HTTP {status}). "
                f"Set {KEY_ENV} to your paid Cavalier licence key."
            ),
        )
    if status != 200 or not isinstance(raw, dict):
        return None, "snapshot", _UNUSABLE
    return raw, "miss", ""


def _http(url: str, body: dict) -> tuple[int, dict[str, str], dict | None]:
    secret = lookup(KEY_ENV) or ""
    if _RESOLVER is None:
        policy = EgressPolicy(_allowlist_path(), "hudson-rock")
    else:
        policy = EgressPolicy(_allowlist_path(), "hudson-rock", resolver=_RESOLVER)
    client = HttpClient(
        "hudson-rock",
        policy=policy,
        cache=HttpCache(data_dir() / "hudsonrock-raw.sqlite", persistence="none"),
        limiter=RateLimiter(data_dir() / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=RATE_PER_SECOND,
        burst=BURST,
        window="rolling",
        timeout=TIMEOUT_SECONDS,
        retries=2,
        auth_scope=_scope(secret),
        transport=_TRANSPORT,
        sleeper=_SLEEPER,
        rng=_RNG or random.random,
    )
    try:
        # The shared client calls RateLimiter.acquire for every attempt.
        response = client.post_json(
            url,
            body,
            headers={"api-key": secret, "accept": "application/json"},
            ttl=0,
        )
    finally:
        client.close()
    payload = None
    if response.body:
        try:
            parsed = json.loads(response.body)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            payload = parsed
    return response.status, {key.lower(): value for key, value in response.headers.items()}, payload


def _accept(url: str, payload: dict) -> tuple[dict | None, str]:
    if _schema_problem(url, payload):
        return None, _UNUSABLE
    if url == SEARCH_URL:
        return _strip_search(payload), ""
    return _strip_overview(payload), ""


def _strip_search(payload: dict) -> dict:
    rows = []
    for item in payload.get("data") or []:
        if not isinstance(item, dict):
            continue
        credentials = []
        for cred in item.get("credentials") or []:
            if not isinstance(cred, dict):
                continue
            domain = cred.get("domain")
            kind = cred.get("type")
            if isinstance(domain, str) and isinstance(kind, str):
                credentials.append({"domain": domain, "type": kind})
        compromised = item.get("date_compromised")
        rows.append(
            {
                "date_compromised": compromised if isinstance(compromised, str) else "",
                "credentials": credentials,
            }
        )
    return {"data": rows, "nextCursor": _cursor(payload)}


def _strip_overview(payload: dict) -> dict:
    rows = []
    for item in payload.get("data") or []:
        if not isinstance(item, dict):
            continue
        apps = [
            value
            for value in (item.get("sensitive_applications") or [])
            if isinstance(value, str) and value.strip()
        ][:20]
        row = {
            "domain": item.get("domain") if isinstance(item.get("domain"), str) else "",
            "compromised_employees": item.get("compromised_employees"),
            "compromised_users": item.get("compromised_users"),
        }
        for name in _OVERVIEW_TIMES:
            if isinstance(item.get(name), str):
                row[name] = item[name]
        if apps:
            row["sensitive_applications"] = apps
        rows.append(row)
    return {"data": rows, "nextCursor": _cursor(payload)}


def _cursor(payload: dict):
    value = payload.get("nextCursor")
    return value if isinstance(value, str) and value else None


def _search_findings(
    payload: dict,
    requested: list[str],
    types: list[str] | None,
    since: str | None,
) -> tuple[list[ExposureFinding], str]:
    selected = list(types or _COUNT_KEYS)
    # Filtered counts are a different measure. Keep them out of the unfiltered row.
    scope = ""
    if types:
        scope += ":types=" + ",".join(sorted(types))
    if since:
        scope += f":since={since}"
    buckets = {domain: {name: 0 for name in selected} for domain in requested}
    first: dict[str, datetime] = {}
    last: dict[str, datetime] = {}
    for item in payload.get("data") or []:
        if not isinstance(item, dict):
            return [], _UNUSABLE
        when = _parse_time(item.get("date_compromised"))
        if when is None:
            return [], _UNUSABLE
        if since and when < _sydney_start(since):
            continue
        for cred in item.get("credentials") or []:
            if not isinstance(cred, dict):
                continue
            bucket = _CRED_BUCKET.get(str(cred.get("type") or ""))
            if bucket is None or bucket not in selected:
                continue
            domain = _attribute(str(cred.get("domain") or ""), requested)
            if domain is None:
                continue
            buckets[domain][bucket] += 1
            first[domain] = when if domain not in first else min(first[domain], when)
            last[domain] = when if domain not in last else max(last[domain], when)
    findings = []
    for domain in requested:
        if domain not in first:
            continue
        findings.append(
            _finding(
                domain,
                buckets[domain],
                first[domain],
                last[domain],
                source_ref=f"search-by-domain:{domain}{scope}",
                data_classes=["credential"],
            )
        )
    return findings, ""


def _overview_findings(payload: dict, domain: str) -> tuple[list[ExposureFinding], str]:
    findings = []
    for item in payload.get("data") or []:
        if not isinstance(item, dict):
            return [], _UNUSABLE
        row_domain = _clean_domain(item.get("domain"))
        if row_domain != domain:
            continue
        employees = _count(item.get("compromised_employees"))
        users = _count(item.get("compromised_users"))
        if employees is None or users is None:
            return [], _UNUSABLE
        stamps = []
        for name in _OVERVIEW_TIMES:
            parsed = _parse_time(item.get(name))
            if parsed is not None:
                stamps.append(parsed)
        if not stamps:
            return [], _UNUSABLE
        apps = [
            value
            for value in (item.get("sensitive_applications") or [])
            if isinstance(value, str) and value.strip()
        ][:20]
        findings.append(
            _finding(
                domain,
                {"employees": employees, "users": users},
                min(stamps),
                max(stamps),
                source_ref=f"search-by-domain/overview:{domain}",
                data_classes=apps or None,
            )
        )
    return findings, ""


def _attribute(credential_domain: str, requested: list[str]) -> str | None:
    if len(requested) == 1:
        return requested[0]
    cred = credential_domain.strip().lower().rstrip(".")
    for domain in requested:
        if cred == domain or (cred.endswith("." + domain) and cred):
            return domain
    return None


def _finding(
    domain: str,
    counts: dict[str, int],
    first: datetime,
    last: datetime,
    *,
    source_ref: str,
    data_classes: list[str] | None,
) -> ExposureFinding:
    terms = get_vendor(VENDOR).terms
    scope = {
        "none": "session_only",
        "metadata": "store_metadata",
        "full": "store_full",
    }[terms.store]
    finding = ExposureFinding(
        finding_id=finding_id(VENDOR, "infostealer_credential", domain, source_ref),
        vendor=VENDOR,
        kind="infostealer_credential",
        subject=Subject(type="domain", value=domain, watchlist_entry=domain),
        observed_at=last,
        first_seen=first,
        licence_scope=scope,
        confidence="vendor_reported",
        counts=counts,
        data_classes=data_classes,
        source_ref=source_ref,
        stix_exportable=False,
        contains_personal_information=False,
    )
    return clamp_to_terms(canonical_finding(finding), terms)


def _remember(findings: list[ExposureFinding], watchlist: Watchlist) -> None:
    if not findings:
        return
    terms = get_vendor(VENDOR).terms
    store = ExposureStore(data_dir() / "exposures.sqlite")
    for finding in findings:
        store.write(finding, terms=terms, watchlist=watchlist, values=None)


def _count(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _sydney_start(day: str) -> datetime:
    return datetime.combine(date.fromisoformat(day), time.min, tzinfo=SYDNEY)


def _latest(findings: list[ExposureFinding]) -> str | None:
    if not findings:
        return None
    latest = max(item.observed_at for item in findings)
    return latest.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _schema_problem(url: str, payload: object) -> str | None:
    if not isinstance(payload, dict):
        return "schema drift: payload was not an object"
    name = (
        "hudsonrock_domain_exposure.response.json"
        if url == SEARCH_URL
        else "hudsonrock_domain_overview.response.json"
    )
    schema = json.loads((_PACKAGE / "schema" / name).read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda item: list(item.absolute_path))
    if not errors:
        return None
    return f"schema drift: {errors[0].message}"


def _read_snapshot(url: str) -> tuple[dict | None, str]:
    env_name = (
        "CYBERAU_HUDSONROCK_SEARCH_SNAPSHOT"
        if url == SEARCH_URL
        else "CYBERAU_HUDSONROCK_OVERVIEW_SNAPSHOT"
    )
    raw = os.environ.get(env_name)
    if not raw:
        return None, ""
    try:
        payload = _read_json(Path(raw))
    except (OSError, json.JSONDecodeError, TypeError):
        return None, _UNUSABLE
    if not isinstance(payload, dict):
        return None, _UNUSABLE
    return payload, ""


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _load_cached(body: bytes) -> dict | None:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _session_cache() -> HttpCache:
    global _SESSION_CACHE
    if _SESSION_CACHE is None:
        _SESSION_CACHE = cache_for_terms(
            data_dir() / "hudsonrock-session.sqlite",
            get_vendor(VENDOR).terms,
        )
    return _SESSION_CACHE


def _allowlist_path() -> Path:
    override = os.environ.get("CYBERAU_EGRESS_ALLOWLIST")
    if override:
        return Path(override)
    return _PACKAGE.parent / "egress-allowlist.yaml"


def _body_bytes(body: dict) -> bytes:
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode()


def _scope(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()[:16]


def _safe(message: str) -> str:
    text = redact(message)
    secret = lookup(KEY_ENV)
    if secret:
        text = text.replace(secret, "[REDACTED]")
    return text


register_connector("hudson-rock", connector)
