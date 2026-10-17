"""Read-only SOCRadar company incidents connector."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Annotated
from zoneinfo import ZoneInfo

import jsonschema
import yaml
from cyberau_common import USER_AGENT
from cyberau_common.egress import EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient
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
from cyberau_premium.paths import data_dir
from cyberau_premium.present import finding_payload
from cyberau_premium.redact import redact_text
from cyberau_premium.store import ExposureStore
from pydantic import Field, ValidationError

DOC_URL = "https://platform.socradar.com/api/company/{company_id}/incidents/v4"
_HOST = "platform.socradar.com"
_SYDNEY = ZoneInfo("Australia/Sydney")
_PAGE_CAP = 100
_SESSION_TTL = 6 * 3600
_SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
_SUB_KIND = {
    "impersonating domain": "brand_impersonation",
    "stolen credential": "breach_credential",
}
_MAIN_KIND = {
    "attack surface management": "attack_surface_issue",
}
_DATE_FORMATS = (
    ("%Y-%m-%d %H:%M:%S", 19),
    ("%Y-%m-%dT%H:%M:%S.%f", 26),
    ("%Y-%m-%dT%H:%M:%S", 19),
    ("%Y-%m-%d", 10),
)
_HOST_NAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE,
)
_REF = re.compile(r"[A-Za-z0-9_-]{1,64}")
_PACKAGE = Path(__file__).resolve().parents[2]
_SYNTHETIC = _PACKAGE / "tests" / "fixtures" / "incidents_v4_synthetic.json"
_RESPONSE_SCHEMA = _PACKAGE / "schema" / "socradar_incidents.response.json"
_CACHE_RANK = {"hit": 0, "miss": 1, "stale": 2, "snapshot": 3}

_TRANSPORT = None
_SLEEPER = None
_RNG = None
_RESOLVER = None
_LIMITER_CLOCK = None
_LIMITER_SLEEPER = None
_CACHES: dict[str, object] = {}


def socradar_incidents(
    since: Annotated[str | None, Field(description="YYYY-MM-DD, Australia/Sydney")] = None,
    until: Annotated[str | None, Field(description="YYYY-MM-DD, Australia/Sydney")] = None,
    severity: str | None = None,
    limit: Annotated[int, Field(ge=1, le=500)] = 100,
) -> dict:
    """Company incidents in a date range, mapped to exposure kinds."""
    problem = _validate(since, until, severity, limit)
    if problem:
        return _envelope([], "snapshot", (problem,))
    config = _config_error()
    if config:
        return _envelope([], "snapshot", (config,))
    watch, watch_problem = _load_watchlist()
    rows, cache, warnings = _collect(
        since=since or None,
        until=until or None,
        severity=_severity(severity),
        limit=limit,
        watchlist=watch,
    )
    if watch_problem:
        warnings.append(watch_problem)
    if watch is not None and rows:
        _store([row.finding for row in rows], watch)
    return _envelope([_record(row) for row in rows], cache, tuple(warnings))


def connector() -> SocradarConnector:
    return SocradarConnector()


class SocradarConnector(PremiumConnector):
    def __init__(self) -> None:
        spec = get_vendor("socradar")
        super().__init__(
            key="socradar",
            server_name="socradar",
            attribution=spec.terms.attribution,
            tools=[
                ToolSpec(
                    "socradar_incidents",
                    (
                        "Company incidents in a date range, mapped to exposure kinds. "
                        "Commercial licence. Session cache. Store metadata only. "
                        "No STIX export. Read only. Ships disabled until enabled."
                    ),
                    socradar_incidents,
                )
            ],
            vendor=spec.server,
            licence_env=tuple(spec.licence_env),
            terms=spec.terms,
            quota=spec.quota,
        )

    def exposure_for(self, watchlist: Watchlist, since: date) -> list[ExposureFinding]:
        problem = _config_error()
        if problem:
            raise ValueError(problem)
        rows, _cache, _warnings = _collect(
            since=since.isoformat(),
            until=None,
            severity=None,
            limit=500,
            watchlist=watchlist,
        )
        matched: list[ExposureFinding] = []
        known = watchlist.known_subjects()
        for row in rows:
            if row.finding.subject.value.casefold() not in known:
                continue
            matched.append(row.finding)
        if matched:
            _store(matched, watchlist)
        return matched

    def health(self, *, live: bool = False, check_schema: bool = False) -> Probe:
        if check_schema:
            problem = schema_problem(_schema_payload())
            if problem:
                return Probe(self.key, False, problem)
            if not live:
                return Probe(self.key, True, "schema ok")
        if lookup("SOCRADAR_API_KEY") is None or lookup("SOCRADAR_COMPANY_ID") is None:
            return Probe(self.key, True, "not configured")
        if _company_id() is None:
            return Probe(self.key, False, "SOCRADAR_COMPANY_ID must be a numeric company id")
        if not live:
            return Probe(self.key, True, "offline ok")
        yesterday = (datetime.now(_SYDNEY).date() - timedelta(days=1)).isoformat()
        payload, _cache, warning = _fetch_page(
            since=yesterday,
            until=None,
            severity=None,
            limit=1,
            page=1,
            force_live=True,
        )
        if warning:
            return Probe(self.key, False, warning)
        problem = schema_problem(payload or {})
        if problem:
            return Probe(self.key, False, problem)
        return Probe(self.key, True, "live ok")


class _Row:
    def __init__(self, finding: ExposureFinding, summary: str) -> None:
        self.finding = finding
        self.summary = summary


def schema_drift(payload: dict) -> str | None:
    """Return a drift message when the incidents payload lost a field we read."""
    if not isinstance(payload, dict):
        return "SOCRadar schema drift, payload is not an object"
    data = payload.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("alarms"), list):
        return "SOCRadar schema drift, missing data.alarms"
    alarms = data["alarms"]
    if not alarms:
        return None
    first = alarms[0]
    if not isinstance(first, dict) or "alarm_id" not in first or "date" not in first:
        return "SOCRadar schema drift, missing alarm_id or date"
    details = first.get("alarm_type_details")
    if details is not None and not isinstance(details, dict):
        return "SOCRadar schema drift, alarm_type_details is not an object"
    return None


def schema_problem(payload: dict) -> str | None:
    drift = schema_drift(payload)
    if drift:
        return drift
    schema = json.loads(_RESPONSE_SCHEMA.read_text(encoding="utf-8"))
    try:
        jsonschema.Draft202012Validator(schema).validate(payload)
    except jsonschema.ValidationError:
        return "SOCRadar schema drift, response does not match socradar_incidents.response.json"
    return None


def _collect(
    *,
    since: str | None,
    until: str | None,
    severity: str | None,
    limit: int,
    watchlist: Watchlist | None,
    force_live: bool = False,
) -> tuple[list[_Row], str, list[str]]:
    problem = _config_error()
    if problem:
        return [], "snapshot", [problem]
    if os.environ.get("CYBERAU_SOCRADAR_SNAPSHOT") and not force_live:
        payload, cache, warning = _read_snapshot()
        if warning or payload is None:
            return [], cache, [warning or "SOCRadar payload was not usable"]
        if payload.get("is_success") is False:
            return [], "snapshot", ["SOCRadar reported an unsuccessful response"]
        drifted = schema_drift(payload)
        if drifted:
            return [], "snapshot", [drifted]
        rows, notes = _map_payload(payload, since, until, severity, watchlist)
        return rows[:limit], "snapshot", notes
    spec = get_vendor("socradar")
    rows: list[_Row] = []
    warnings: list[str] = []
    cache = "hit"
    for page in range(1, spec.max_pages + 1):
        payload, page_cache, warning = _fetch_page(
            since=since,
            until=until,
            severity=severity,
            limit=limit,
            page=page,
            force_live=force_live,
        )
        cache = _weaker(cache, page_cache)
        if warning:
            warnings.append(warning)
            break
        if payload is None:
            warnings.append("SOCRadar payload was not usable")
            break
        page_rows, notes = _map_payload(payload, since, until, severity, watchlist)
        warnings.extend(notes)
        rows.extend(page_rows)
        if len(rows) >= limit:
            break
        data = payload.get("data") if isinstance(payload, dict) else None
        alarms = data.get("alarms") if isinstance(data, dict) else None
        if not alarms:
            break
        total = data.get("total_pages") if isinstance(data, dict) else None
        if not isinstance(total, int):
            warnings.append("SOCRadar did not return total_pages. Stopped after one page.")
            break
        if page >= total:
            break
        if page == spec.max_pages and total > spec.max_pages:
            warnings.append(
                f"Stopped at {spec.max_pages} pages. The catalogue max_pages ceiling was reached."
            )
    return rows[:limit], cache, warnings


def _fetch_page(
    *,
    since: str | None,
    until: str | None,
    severity: str | None,
    limit: int,
    page: int,
    force_live: bool,
) -> tuple[dict | None, str, str]:
    company = _company_id()
    if company is None:
        detail = _config_error() or "SOCRADAR_COMPANY_ID must be a numeric company id"
        return None, "snapshot", detail
    url = f"https://{_HOST}/api/company/{company}/incidents/v4"
    params = _params(since=since, until=until, severity=severity, limit=limit, page=page)
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    cache = _session_cache()
    cache_key = cache.key("GET", url, params, b"", "socradar")
    if offline:
        cached = cache.get(cache_key)
        if cached is None:
            return None, "snapshot", "unavailable"
        state = "hit" if cache.fresh(cached) else "stale"
        return _load(cached.body.decode("utf-8", "replace")), state, ""
    client = _client(cache, offline=False)
    try:
        response = client.get(
            url,
            params=params,
            headers=_headers(),
            ttl=_SESSION_TTL,
            skip_cache=force_live,
        )
    except Exception as exc:
        return None, "snapshot", _safe(str(exc))
    finally:
        client.close()
    if response.status in {401, 403}:
        return None, response.cache, _auth_message(response.status)
    if response.status == 429:
        return (
            None,
            response.cache,
            ("SOCRadar rate limited the request (HTTP 429). Retry-After is honoured."),
        )
    if response.status >= 400:
        return None, response.cache, f"SOCRadar returned HTTP {response.status}"
    payload = _load(response.body.decode("utf-8", "replace"))
    if payload is None:
        return None, response.cache, "SOCRadar payload was not usable"
    if payload.get("is_success") is False:
        return None, response.cache, "SOCRadar reported an unsuccessful response"
    problem = schema_drift(payload)
    if problem:
        return None, response.cache, problem
    return payload, response.cache, ""


def _map_payload(
    payload: dict,
    since: str | None,
    until: str | None,
    severity: str | None,
    watchlist: Watchlist | None,
) -> tuple[list[_Row], list[str]]:
    data = payload.get("data") if isinstance(payload, dict) else None
    alarms = data.get("alarms") if isinstance(data, dict) else None
    if not isinstance(alarms, list):
        return [], ["SOCRadar schema drift, missing data.alarms"]
    rows: list[_Row] = []
    unmapped = 0
    undated = 0
    for alarm in alarms:
        if not isinstance(alarm, dict):
            undated += 1
            continue
        if severity and str(alarm.get("alarm_risk_level") or "").upper() != severity:
            continue
        observed = _parse_date(str(alarm.get("date") or ""))
        if observed is None:
            undated += 1
            continue
        day = observed.date().isoformat()
        if since and day < since:
            continue
        if until and day > until:
            continue
        kind = _kind(alarm)
        if kind is None:
            unmapped += 1
            continue
        subject = _choose_subject(alarm, watchlist)
        if subject is None:
            undated += 1
            continue
        source_ref = _source_ref(alarm.get("alarm_id"))
        if source_ref is None:
            undated += 1
            continue
        subject_type, subject_value = subject
        finding = ExposureFinding(
            finding_id=finding_id("socradar", kind, subject_value, source_ref),
            vendor="socradar",
            kind=kind,
            subject=Subject(type=subject_type, value=subject_value),
            observed_at=observed,
            first_seen=observed,
            licence_scope="store_metadata",
            confidence="vendor_reported",
            counts={"alarms": 1},
            data_classes=_data_classes(kind),
            source_ref=source_ref,
            stix_exportable=False,
            contains_personal_information=kind == "breach_credential",
        )
        finding = clamp_to_terms(canonical_finding(finding), get_vendor("socradar").terms)
        text = alarm.get("alarm_text")
        summary = _free_text(text) if isinstance(text, str) and text.strip() else ""
        rows.append(_Row(finding, summary))
    notes = []
    if unmapped:
        notes.append(f"{unmapped} incidents omitted: alarm type has no confirmed mapping")
    if undated:
        notes.append(f"{undated} incidents omitted: date, subject, or record id was not usable")
    return rows, notes


def _kind(alarm: dict) -> str | None:
    details = alarm.get("alarm_type_details")
    if not isinstance(details, dict):
        return None
    sub = str(details.get("alarm_sub_type") or "").strip().casefold()
    main = str(details.get("alarm_main_type") or "").strip().casefold()
    if sub in _SUB_KIND:
        return _SUB_KIND[sub]
    if main in _MAIN_KIND:
        return _MAIN_KIND[main]
    return None


def _data_classes(kind: str) -> list[str]:
    if kind == "breach_credential":
        return ["credential"]
    if kind == "brand_impersonation":
        return ["domain"]
    return ["exposure"]


def _choose_subject(alarm: dict, watchlist: Watchlist | None) -> tuple[str, str] | None:
    options = _subjects(alarm)
    if watchlist is not None:
        known = watchlist.known_subjects()
        for subject_type, value in options:
            if value.casefold() in known:
                return subject_type, value
    return options[0] if options else None


def _subjects(alarm: dict) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    asset = alarm.get("alarm_asset")
    if isinstance(asset, str):
        classified = _classify(asset)
        if classified:
            found.append(classified)
    related = alarm.get("alarm_related_assets")
    if isinstance(related, list):
        for item in related:
            found.extend(_related_values(item))
    return found


def _related_values(item) -> list[tuple[str, str]]:
    values: list[str] = []
    if isinstance(item, str):
        values.append(item)
    elif isinstance(item, dict):
        raw = item.get("value")
        if isinstance(raw, str):
            values.append(raw)
        elif isinstance(raw, list):
            values.extend(part for part in raw if isinstance(part, str))
    found = []
    for value in values:
        classified = _classify(value)
        if classified:
            found.append(classified)
    return found


def _classify(value: str) -> tuple[str, str] | None:
    text = value.strip()
    if not text or len(text) > 253 or any(ord(char) < 32 for char in text):
        return None
    if "@" in text:
        domain = text.rsplit("@", 1)[-1].strip().rstrip(".").lower()
        if _HOST_NAME.fullmatch(domain):
            return ("email_domain", domain)
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        address = None
    if address is not None:
        return ("ip", address.compressed)
    if _HOST_NAME.fullmatch(text):
        return ("domain", text.lower().rstrip("."))
    return ("brand", text)


def _source_ref(value) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        text = str(value)
    elif isinstance(value, str):
        text = value.strip()
    else:
        return None
    if _REF.fullmatch(text):
        return text
    return None


def _parse_date(value: str) -> datetime | None:
    for fmt, size in _DATE_FORMATS:
        try:
            parsed = datetime.strptime(value[:size], fmt)
        except (ValueError, IndexError):
            continue
        return parsed.replace(tzinfo=UTC)
    return None


def _params(
    *,
    since: str | None,
    until: str | None,
    severity: str | None,
    limit: int,
    page: int,
) -> dict:
    params: dict = {
        "limit": str(min(limit, _PAGE_CAP)),
        "page": str(page),
        "include_total_records": "true",
        "include_alarm_details": "true",
    }
    if since:
        params["start_date"] = since
    if until:
        params["end_date"] = until
    if severity:
        params["severities"] = [severity]
    return params


def _headers() -> dict[str, str]:
    secret = lookup("SOCRADAR_API_KEY") or ""
    return {"Api-Key": secret}


def _client(cache, *, offline: bool) -> HttpClient:
    policy_kwargs = {}
    if _RESOLVER is not None:
        policy_kwargs["resolver"] = _RESOLVER
    client_kwargs = {}
    if _TRANSPORT is not None:
        client_kwargs["transport"] = _TRANSPORT
    if _SLEEPER is not None:
        client_kwargs["sleeper"] = _SLEEPER
    if _RNG is not None:
        client_kwargs["rng"] = _RNG
    limiter_kwargs = {}
    if _LIMITER_CLOCK is not None:
        limiter_kwargs["clock"] = _LIMITER_CLOCK
    if _LIMITER_SLEEPER is not None:
        limiter_kwargs["sleeper"] = _LIMITER_SLEEPER
    return HttpClient(
        "socradar",
        policy=EgressPolicy(_allowlist(), "socradar", **policy_kwargs),
        cache=cache,
        limiter=RateLimiter(data_dir() / "socradar-rate-limit.sqlite", **limiter_kwargs),
        user_agent=USER_AGENT,
        rate=1.0,
        burst=5,
        window="rolling",
        timeout=60,
        auth_scope="socradar",
        offline=offline,
        **client_kwargs,
    )


def _session_cache():
    path = data_dir() / "socradar-http-cache.sqlite"
    key = str(path)
    cache = _CACHES.get(key)
    if cache is None:
        cache = cache_for_terms(path, get_vendor("socradar").terms)
        _CACHES[key] = cache
    return cache


def _read_snapshot() -> tuple[dict | None, str, str]:
    raw = os.environ.get("CYBERAU_SOCRADAR_SNAPSHOT")
    path = Path(raw) if raw else _SYNTHETIC
    try:
        payload = _load(path.read_text(encoding="utf-8"))
    except OSError:
        return None, "snapshot", "unavailable"
    if payload is None:
        return None, "snapshot", "SOCRadar payload was not usable"
    return payload, "snapshot", ""


def _schema_payload() -> dict:
    raw = os.environ.get("CYBERAU_SOCRADAR_SNAPSHOT")
    path = Path(raw) if raw else _SYNTHETIC
    try:
        payload = _load(path.read_text(encoding="utf-8"))
    except OSError:
        return {}
    return payload or {}


def _validate(
    since: str | None,
    until: str | None,
    severity: str | None,
    limit: int,
) -> str:
    if since and _day(since) is None:
        return "since must be YYYY-MM-DD"
    if until and _day(until) is None:
        return "until must be YYYY-MM-DD"
    if since and until and since > until:
        return "since must be on or before until"
    if severity and _severity(severity) is None:
        allowed = ", ".join(_SEVERITIES)
        return f"severity must be one of {allowed}"
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        return "limit must be between 1 and 500"
    return ""


def _day(value: str) -> str | None:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date().isoformat()
    except ValueError:
        return None


def _severity(value: str | None) -> str | None:
    if value is None or not str(value).strip():
        return None
    token = str(value).strip().upper()
    if token in _SEVERITIES:
        return token
    return None


def _company_id() -> str | None:
    raw = lookup("SOCRADAR_COMPANY_ID")
    if raw is None:
        return None
    text = raw.strip()
    if re.fullmatch(r"[0-9]+", text):
        return text
    return None


def _config_error() -> str:
    missing = []
    if lookup("SOCRADAR_API_KEY") is None:
        missing.append("SOCRADAR_API_KEY")
    if lookup("SOCRADAR_COMPANY_ID") is None:
        missing.append("SOCRADAR_COMPANY_ID")
    if missing:
        return "Set " + " and ".join(missing) + "."
    if _company_id() is None:
        return "SOCRADAR_COMPANY_ID must be a numeric company id."
    return ""


def _auth_message(status: int) -> str:
    if status == 403:
        return (
            "SOCRadar refused the request (HTTP 403). "
            "Check SOCRADAR_API_KEY and SOCRADAR_COMPANY_ID."
        )
    return "SOCRadar refused the request (HTTP 401). Check SOCRADAR_API_KEY."


def _free_text(value: str) -> str:
    secret = lookup("SOCRADAR_API_KEY")
    if secret:
        value = value.replace(secret, "[REDACTED]")
    return untrusted_text(redact(redact_text(value)), "socradar")


def _record(row: _Row) -> dict:
    payload = finding_payload(row.finding)
    if row.summary:
        payload["summary"] = row.summary
    return payload


def _store(findings: list[ExposureFinding], watchlist: Watchlist) -> None:
    store = ExposureStore(data_dir() / "intel.sqlite")
    terms = get_vendor("socradar").terms
    for finding in findings:
        store.write(finding, terms=terms, watchlist=watchlist)


def _load_watchlist() -> tuple[Watchlist | None, str]:
    path = data_dir() / "watchlist.yaml"
    if not path.exists():
        return None, ""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return None, "watchlist.yaml was not usable"
    if not isinstance(raw, dict):
        return None, "watchlist.yaml was not usable"
    try:
        return Watchlist.model_validate(raw), ""
    except ValidationError:
        return None, "watchlist.yaml was not usable"


def _envelope(data, cache: str, warnings: tuple[str, ...] | list[str] = ()) -> dict:
    safe = tuple(_safe(item) for item in warnings)
    return envelope(
        "socradar",
        data,
        urls=[DOC_URL],
        cache=cache,
        warnings=safe,
        attribution=get_vendor("socradar").terms.attribution,
    )


def _safe(text: str) -> str:
    cleaned = redact(text)
    secret = lookup("SOCRADAR_API_KEY")
    if secret:
        cleaned = cleaned.replace(secret, "[REDACTED]")
    return cleaned


def _weaker(left: str, right: str) -> str:
    if _CACHE_RANK[right] > _CACHE_RANK[left]:
        return right
    return left


def _load(text: str) -> dict | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _allowlist() -> Path:
    override = os.environ.get("CYBERAU_EGRESS_ALLOWLIST")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("socradar", connector)
