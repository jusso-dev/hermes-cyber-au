"""Read-only SpyCloud Enterprise Protection connector.

Records stay in the session cache. Breach catalogue metadata is kept for 24 hours.
No licence key is bundled. The server ships disabled.
"""

import json
import os
import re
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated, Literal
from zoneinfo import ZoneInfo

import yaml
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
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
from jsonschema import Draft202012Validator
from pydantic import Field

SYDNEY = ZoneInfo("Australia/Sydney")
# Reference "Get all records in watchlist": server api.spycloud.io/enterprise-v2,
# path /breach/data/watchlist. Catalogue: /breach/catalog/{id}.
WATCHLIST_URL = "https://api.spycloud.io/enterprise-v2/breach/data/watchlist"
CATALOG_ROOT = "https://api.spycloud.io/enterprise-v2/breach/catalog/"
IDENTIFIERS_URL = "https://api.spycloud.io/enterprise-v2/watchlist/identifiers"
HOST = "api.spycloud.io"
DOCS = "docs/connectors/spycloud.md"

# No published quota. Stay at one request a second and honour Retry-After.
# HttpClient reserves once more on the same limiter, so the burst leaves room.
_RATE = 1.0
_BURST = 4
_RECORD_TTL = 3600
_CATALOG_TTL = 24 * 3600

_PACKAGE = Path(__file__).resolve().parents[2]
_FIXTURES = _PACKAGE / "tests" / "fixtures"
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_BREACH_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
_CLASS_KEY = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
_WATCHLIST_TYPES = {"email", "domain", "subdomain", "ip"}
_RECORD_TYPES = {"corporate", "infected", "email_domain", "target_domain"}
_SECRET_KEYS = {
    "password",
    "password_plaintext",
    "password_hash",
    "passwd",
    "pwd",
    "username",
    "email",
    "cookie",
    "cookies",
    "form_cookies_data",
    "form_post_data",
    "ssn",
    "dob",
    "phone",
    "bank_number",
    "cc_number",
    "credit_card",
}
_CLASS_FOR = {
    "email": "email address",
    "username": "username",
    "password": "password",
    "password_plaintext": "password",
    "password_hash": "password",
    "domain": "domain",
    "target_domain": "target domain",
    "target_url": "url",
    "ip": "ip address",
    "ip_addresses": "ip address",
    "infected_machine_id": "infected device",
    "phone": "phone",
}
_PI_KEYS = {"email", "username", "phone", "ip", "ip_addresses", "dob"}

_TRANSPORT = None
_SLEEPER = None
_RNG = None
_RESOLVER = None
_SESSION: HttpCache | None = None
_SESSION_DIR: str | None = None

Since = Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")]
Limit = Annotated[int, Field(ge=1, le=1000)]
WatchType = Literal["email", "domain", "subdomain", "ip"]
RecordType = Literal["corporate", "infected", "email_domain", "target_domain"]


def reset_runtime() -> None:
    """Drop process caches and test doubles. Used by the connector tests."""
    global _SESSION, _SESSION_DIR, _TRANSPORT, _SLEEPER, _RNG, _RESOLVER
    _SESSION = None
    _SESSION_DIR = None
    _TRANSPORT = None
    _SLEEPER = None
    _RNG = None
    _RESOLVER = None


def _attribution() -> str:
    return get_vendor("spycloud").terms.attribution


def _clean(message: str) -> str:
    text = redact(message)
    secret = lookup("SPYCLOUD_API_KEY")
    if secret and secret in text:
        text = text.replace(secret, "[REDACTED]")
    return text


def _missing_key() -> str:
    return (
        "SPYCLOUD_API_KEY is not set. SpyCloud is off by default until you bring your own licence."
    )


def _wrap(value: str) -> str:
    return untrusted_text(redact_text(value), "spycloud")


def _envelope(
    data,
    cache: str,
    *,
    warnings: tuple[str, ...] = (),
    url: str = WATCHLIST_URL,
) -> dict:
    state = cache if cache in {"hit", "miss", "stale", "snapshot"} else "snapshot"
    return envelope(
        "spycloud",
        data,
        urls=[url],
        cache=state,
        warnings=tuple(_clean(item) for item in warnings),
        attribution=_attribution(),
    )


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


def _session_cache() -> HttpCache:
    global _SESSION, _SESSION_DIR
    directory = str(data_dir())
    if _SESSION is None or _SESSION_DIR != directory:
        _SESSION = cache_for_terms(
            Path(directory) / "spycloud-session.sqlite",
            get_vendor("spycloud").terms,
        )
        _SESSION_DIR = directory
    return _SESSION


def _catalog_cache() -> HttpCache:
    return HttpCache(data_dir() / "spycloud-catalog.sqlite")


def _scope() -> str:
    return "keyed" if lookup("SPYCLOUD_API_KEY") else "anonymous"


def _parse_body(body: bytes) -> tuple[dict | None, str]:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None, "SpyCloud payload was not usable"
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None, "SpyCloud payload was not usable"
    if not isinstance(payload, dict):
        return None, "SpyCloud payload was not usable"
    return payload, ""


def _read_json_file(path: Path) -> tuple[dict | None, str]:
    try:
        body = path.read_text(encoding="utf-8")
    except OSError:
        return None, "unavailable"
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return None, "SpyCloud payload was not usable"
    if not isinstance(payload, dict):
        return None, "SpyCloud payload was not usable"
    return payload, ""


def _policy() -> EgressPolicy:
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    if _RESOLVER is None:
        return EgressPolicy(allowlist, "spycloud")
    return EgressPolicy(allowlist, "spycloud", resolver=_RESOLVER)


def _http_get(
    url: str,
    params: dict | None,
    *,
    ttl: int,
    cache: HttpCache,
    force_live: bool,
) -> tuple[bytes | None, str, str]:
    secret = lookup("SPYCLOUD_API_KEY")
    if secret is None:
        return None, "snapshot", _missing_key()
    scope = _scope()
    key = cache.key("GET", url, params, b"", scope)
    limiter = RateLimiter(data_dir() / "rate_limit.sqlite", sleeper=_SLEEPER)
    try:
        limiter.acquire(f"spycloud:{HOST}", rate=_RATE, burst=_BURST, window="rolling")
    except Exception as exc:
        return _from_error(cache, key, exc, force_live)
    client = HttpClient(
        "spycloud",
        policy=_policy(),
        cache=cache,
        limiter=limiter,
        user_agent=USER_AGENT,
        rate=_RATE,
        burst=_BURST,
        window="rolling",
        timeout=30,
        transport=_TRANSPORT,
        sleeper=_SLEEPER,
        rng=_RNG,
        auth_scope=scope,
    )
    try:
        try:
            response = client.get(
                url,
                params=params,
                headers={"X-API-KEY": secret},
                ttl=ttl,
                skip_cache=force_live,
            )
        except Exception as exc:
            return _from_error(cache, key, exc, force_live)
    finally:
        client.close()
    if response.status in {401, 403}:
        return (
            None,
            response.cache,
            f"SpyCloud refused the key in SPYCLOUD_API_KEY (HTTP {response.status}).",
        )
    if response.status == 429:
        retry = response.headers.get("retry-after", "")
        detail = "SpyCloud rate limit (HTTP 429)."
        if retry:
            detail = f"{detail} Retry-After: {retry}."
        return None, response.cache, detail
    if response.status >= 400:
        return None, response.cache, f"SpyCloud returned HTTP {response.status}."
    return response.body, response.cache, ""


def _from_error(cache: HttpCache, key: str, exc: Exception, force_live: bool):
    if not force_live:
        cached = cache.get(key)
        if cached is not None and cache.within_stale(cached, 86400):
            return cached.body, "stale", ""
    message = _clean(str(exc)) or "unavailable"
    return None, "snapshot", message


def _fetch_json(
    url: str,
    params: dict | None,
    *,
    ttl: int,
    cache_factory: Callable[[], HttpCache],
    snapshot_var: str,
    force_live: bool = False,
    skip_cache: bool = False,
) -> tuple[dict | None, str, str]:
    override = os.environ.get(snapshot_var)
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    if override and not force_live:
        payload, problem = _read_json_file(Path(override))
        if problem:
            return None, "snapshot", problem
        return payload, "snapshot", ""
    if offline or lookup("SPYCLOUD_API_KEY"):
        cache = cache_factory()
        key = cache.key("GET", url, params, b"", _scope())
        if not force_live and not skip_cache:
            cached = cache.get(key)
            if cached is not None and (offline or cache.fresh(cached)):
                payload, problem = _parse_body(cached.body)
                state = "stale" if offline else "hit"
                if problem:
                    return None, state, problem
                return payload, state, ""
        if offline:
            return None, "snapshot", "unavailable"
        body, state, warning = _http_get(
            url,
            params,
            ttl=ttl,
            cache=cache,
            force_live=force_live or skip_cache,
        )
    else:
        return None, "snapshot", _missing_key()
    if warning and body is None:
        return None, state, warning
    if body is None:
        return None, "snapshot", warning or "unavailable"
    payload, problem = _parse_body(body)
    if problem:
        return None, state, problem
    return payload, state, ""


def _result_rows(payload: dict) -> list | None:
    if not isinstance(payload, dict):
        return None
    if isinstance(payload.get("results"), list):
        return payload["results"]
    data = payload.get("data")
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        return data["results"]
    if payload.get("hits") == 0 and not isinstance(payload.get("results"), str):
        return []
    return None


def _catalog_record(payload: dict) -> dict | None:
    if not isinstance(payload, dict):
        return None
    rows = payload.get("results")
    if isinstance(rows, list):
        if not rows:
            return {}
        first = rows[0]
        return first if isinstance(first, dict) else None
    if any(name in payload for name in ("title", "id", "num_records")):
        return payload
    return None


def _validator(filename: str) -> Draft202012Validator:
    schema = json.loads((_PACKAGE / "schema" / filename).read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def _missing_required(row: dict, filename: str) -> list[str]:
    schema = json.loads((_PACKAGE / "schema" / filename).read_text(encoding="utf-8"))
    return [name for name in schema.get("required") or [] if name not in row]


def schema_drift(payload: dict, *, kind: str) -> str | None:
    """Return a drift message, or None when the payload still matches the schema."""
    if kind == "watchlist":
        rows = _result_rows(payload)
        if rows is None:
            return "SpyCloud watchlist payload has no results list"
        if not rows:
            return None
        row = rows[0]
        filename = "spycloud_watchlist_exposure.response.json"
        label = "watchlist"
    else:
        row = _catalog_record(payload)
        if row is None:
            return "SpyCloud breach catalogue payload was not usable"
        if not row:
            return None
        filename = "spycloud_breach_info.response.json"
        label = "breach catalogue"
    if not isinstance(row, dict):
        return f"SpyCloud schema drift, {label} record is not an object"
    missing = _missing_required(row, filename)
    if missing:
        return "SpyCloud schema drift, missing " + ", ".join(missing)
    errors = sorted(_validator(filename).iter_errors(row), key=lambda item: list(item.path))
    if errors:
        return f"SpyCloud schema drift, {label} {errors[0].message}"
    return None


def _schema_sample(env_name: str, default: Path) -> dict:
    raw = os.environ.get(env_name)
    path = Path(raw) if raw else default
    payload, _problem = _read_json_file(path)
    return payload or {}


def _parse_time(value) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _valid_date(value: str) -> bool:
    if not _DATE.fullmatch(value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return False
    return True


def _domain(record: dict) -> str | None:
    for key in ("domain", "email_domain", "target_domain"):
        value = record.get(key)
        if isinstance(value, str) and value.strip() and "@" not in value:
            return value.strip().casefold().rstrip(".")
    email = record.get("email")
    if isinstance(email, str) and "@" in email:
        host = email.split("@", 1)[1].strip().casefold().rstrip(".")
        if host:
            return host
    return None


def _ip(record: dict) -> str | None:
    values: list = []
    raw = record.get("ip_addresses")
    if isinstance(raw, list):
        values.extend(raw)
    if isinstance(record.get("ip"), str):
        values.append(record["ip"])
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _infected(record: dict) -> bool:
    return bool(record.get("infected_machine_id") or record.get("log_id"))


def _inferred_type(record: dict) -> str:
    if _infected(record):
        return "infected"
    if record.get("target_domain") and not record.get("domain") and not record.get("email"):
        return "target_domain"
    if record.get("email") and not record.get("domain"):
        return "email_domain"
    return "corporate"


def _summary_type(record: dict, requested: str | None) -> str:
    if requested:
        return requested
    return _inferred_type(record)


def _keep(record: dict, *, since: str | None, record_type: str | None, watchlist_type: str | None):
    observed = _parse_time(record.get("spycloud_publish_date"))
    if since:
        if observed is None or observed.astimezone(SYDNEY).date().isoformat() < since:
            return False
    if record_type == "infected" and not _infected(record):
        return False
    if record_type == "corporate" and _infected(record):
        return False
    if record_type == "email_domain" and not isinstance(record.get("email"), str):
        return False
    if record_type == "target_domain" and not record.get("target_domain"):
        return False
    if watchlist_type == "email" and not isinstance(record.get("email"), str):
        return False
    if watchlist_type == "domain" and not record.get("domain"):
        return False
    if watchlist_type == "subdomain" and not record.get("target_subdomain"):
        return False
    if watchlist_type == "ip" and _ip(record) is None:
        return False
    return True


def _severity(record: dict) -> int | None:
    value = record.get("severity")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _present(value) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list | dict):
        return bool(value)
    return True


def _classes(record: dict) -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()
    for key in sorted(record):
        label = _CLASS_FOR.get(key)
        if label is None and key not in _SECRET_KEYS and _CLASS_KEY.fullmatch(key):
            continue
        if label and label not in seen and _present(record.get(key)):
            seen.add(label)
            labels.append(label)
    return labels


def _has_pi(record: dict) -> bool:
    return any(_present(record.get(key)) for key in _PI_KEYS)


def _subject(record: dict, watchlist_type: str | None) -> Subject | None:
    if watchlist_type == "ip" or (watchlist_type is None and _ip(record) and not _domain(record)):
        address = _ip(record)
        if address:
            return Subject(type="ip", value=address)
    domain = _domain(record)
    if not domain:
        return None
    email_only = isinstance(record.get("email"), str) and not record.get("domain")
    if watchlist_type == "email" or email_only:
        return Subject(type="email_domain", value=domain)
    return Subject(type="domain", value=domain)


def _finding(record: dict, *, requested: str | None, watchlist_type: str | None):
    document_id = record.get("document_id")
    if not isinstance(document_id, str) or not document_id.strip():
        return None
    subject = _subject(record, watchlist_type)
    observed = _parse_time(record.get("spycloud_publish_date"))
    if subject is None or observed is None:
        return None
    kind = "infostealer_credential" if _infected(record) else "breach_credential"
    if requested == "infected":
        kind = "infostealer_credential"
    counts = {"records": 1}
    severity = _severity(record)
    if severity is not None:
        counts["severity"] = severity
    classes = _classes(record)
    finding = ExposureFinding(
        finding_id=finding_id("spycloud", kind, subject.value, document_id),
        vendor="spycloud",
        kind=kind,
        subject=subject,
        observed_at=observed,
        first_seen=observed,
        licence_scope="store_metadata",
        confidence="vendor_reported",
        counts=counts,
        data_classes=classes or None,
        source_ref=document_id,
        stix_exportable=False,
        contains_personal_information=_has_pi(record),
    )
    return clamp_to_terms(canonical_finding(finding), get_vendor("spycloud").terms)


def local_watchlist() -> Watchlist | None:
    """Load the user-owned org-exposure watchlist. Nothing is shipped with the connector."""
    raw = os.environ.get("CYBERAU_ORG_WATCHLIST")
    if not raw:
        return None
    path = Path(raw)
    if not path.is_file():
        return None
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(loaded, dict):
        return None
    return Watchlist.model_validate(loaded)


def local_domains(watch: Watchlist) -> set[str]:
    found: set[str] = set()
    for item in [*watch.domains, *watch.email_domains]:
        if isinstance(item, str) and item.strip():
            found.add(item.strip().casefold().rstrip("."))
    for subsidiary in watch.subsidiaries:
        if not isinstance(subsidiary, dict):
            continue
        for domain in subsidiary.get("domains") or []:
            if isinstance(domain, str) and domain.strip():
                found.add(domain.strip().casefold().rstrip("."))
    excluded = {item.casefold() for item in watch.exclude}
    return {item for item in found if item not in excluded}


def remote_domains(identifiers: list[dict]) -> set[str]:
    found: set[str] = set()
    for item in identifiers:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("identifier_type") or "").casefold()
        name = str(item.get("identifier_name") or "").strip().casefold().rstrip(".")
        if not name or kind == "ip":
            continue
        if kind == "email" and "@" in name:
            name = name.split("@", 1)[1]
        if name:
            found.add(name)
    return found


def compare_watchlists(local: Watchlist, identifiers: list[dict]) -> dict:
    """Domains present on only one of the local watchlist and the SpyCloud watchlist."""
    left = local_domains(local)
    right = remote_domains(identifiers)
    return {
        "missing_from_spycloud": sorted(left - right),
        "missing_from_local": sorted(right - left),
    }


def doctor_report(*, enabled: bool, key_present: bool, gaps: dict | None = None) -> str:
    if not enabled:
        state = f"off by default: licence terms ({DOCS})"
    elif not key_present:
        state = "on, key missing"
    else:
        state = "on"
    lines = [state]
    if gaps:
        missing_remote = gaps.get("missing_from_spycloud") or []
        missing_local = gaps.get("missing_from_local") or []
        if missing_remote:
            lines.append("missing from SpyCloud: " + ", ".join(missing_remote))
        if missing_local:
            lines.append("missing from local watchlist: " + ", ".join(missing_local))
    return "\n".join(lines)


def _store_findings(findings: list[ExposureFinding]) -> str | None:
    if not findings:
        return None
    watch = local_watchlist()
    if watch is None:
        return "Local org-exposure watchlist was not found, so records were not stored."
    store = ExposureStore(data_dir() / "intel.sqlite")
    terms = get_vendor("spycloud").terms
    for finding in findings:
        store.write(finding, terms=terms, watchlist=watch)
    return None


def _validate_watchlist(since, watchlist_type, record_type, limit) -> str:
    if since is not None and (not isinstance(since, str) or not _valid_date(since)):
        return "since must be YYYY-MM-DD"
    if watchlist_type is not None and watchlist_type not in _WATCHLIST_TYPES:
        return "watchlist_type is not a known value"
    if record_type is not None and record_type not in _RECORD_TYPES:
        return "type is not a known value"
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
        return "limit must be between 1 and 1000"
    return ""


def _collect_watchlist(
    *,
    since: str | None,
    watchlist_type: str | None,
    record_type: str | None,
    limit: int,
    force_live: bool = False,
) -> tuple[list[ExposureFinding], dict | None, str, tuple[str, ...]]:
    params: dict[str, str] = {}
    if since:
        params["since"] = since
    if watchlist_type:
        params["watchlist_type"] = watchlist_type
    if record_type:
        params["type"] = record_type
    pages = get_vendor("spycloud").max_pages
    rows: list[dict] = []
    cursor = ""
    cache = "snapshot"
    warnings: list[str] = []
    query_params: dict | None = params or None
    for _page in range(pages):
        if cursor:
            query_params = {**params, "cursor": cursor}
        payload, cache, warning = _fetch_json(
            WATCHLIST_URL,
            query_params,
            ttl=_RECORD_TTL,
            cache_factory=_session_cache,
            snapshot_var="CYBERAU_SPYCLOUD_WATCHLIST_SNAPSHOT",
            force_live=force_live,
            # Cursor tokens expire in about two minutes. Do not replay a cached page.
            skip_cache=bool(cursor),
        )
        if warning:
            warnings.append(warning)
        if payload is None:
            break
        batch = _result_rows(payload)
        if batch is None:
            warnings.append("SpyCloud watchlist payload was not usable")
            break
        rows.extend(item for item in batch if isinstance(item, dict))
        next_cursor = payload.get("cursor")
        if cache == "snapshot" or not isinstance(next_cursor, str) or not next_cursor:
            break
        cursor = next_cursor
        if len(rows) >= limit:
            break
    if not rows and warnings:
        return [], None, cache, tuple(warnings)
    kept = [
        row
        for row in rows
        if _keep(row, since=since, record_type=record_type, watchlist_type=watchlist_type)
    ]
    findings: list[ExposureFinding] = []
    summary_rows: list[tuple[str, int | None]] = []
    for row in kept:
        built = _finding(row, requested=record_type, watchlist_type=watchlist_type)
        if built is None:
            continue
        findings.append(built)
        summary_rows.append((_summary_type(row, record_type), _severity(row)))
        if len(findings) >= limit:
            break
    if kept and not findings and not warnings:
        warnings.append("SpyCloud watchlist payload was not usable")
        return [], None, cache, tuple(warnings)
    note = _store_findings(findings)
    if note:
        warnings.append(note)
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for record_label, severity in summary_rows:
        by_type[record_label] = by_type.get(record_label, 0) + 1
        if severity is not None:
            label = str(severity)
            by_severity[label] = by_severity.get(label, 0) + 1
    data = {
        "records": [finding_payload(item) for item in findings],
        "summary": {"by_type": by_type, "by_severity": by_severity},
    }
    return findings, data, cache, tuple(warnings)


def spycloud_watchlist_exposure(
    since: Since | None = None,
    watchlist_type: WatchType | None = None,
    type: RecordType | None = None,
    limit: Limit = 100,
) -> dict:
    problem = _validate_watchlist(since, watchlist_type, type, limit)
    if problem:
        return _envelope(None, "snapshot", warnings=(problem,))
    _findings, data, cache, warnings = _collect_watchlist(
        since=since,
        watchlist_type=watchlist_type,
        record_type=type,
        limit=limit,
    )
    return _envelope(data, cache, warnings=warnings)


def _breach_payload(record: dict, breach_id: str) -> dict | None:
    title = record.get("title")
    published = record.get("spycloud_publish_date")
    count = record.get("num_records")
    if not isinstance(title, str) or not isinstance(published, str) or not isinstance(count, int):
        return None
    assets = record.get("assets") if isinstance(record.get("assets"), dict) else {}
    classes = []
    for key in sorted(assets):
        label = _CLASS_FOR.get(str(key))
        if label is None and _CLASS_KEY.fullmatch(str(key)):
            label = str(key)
        if label:
            classes.append(_wrap(label))
    payload = {
        "breach_id": str(record.get("id", breach_id)),
        "title": _wrap(title),
        "publish_date": published,
        "record_count": count,
        "data_classes": classes,
    }
    description = record.get("description")
    if isinstance(description, str) and description.strip():
        payload["description"] = _wrap(description)
    return payload


def spycloud_breach_info(breach_id: str) -> dict:
    if not isinstance(breach_id, str) or not _BREACH_ID.fullmatch(breach_id):
        return _envelope(
            None,
            "snapshot",
            warnings=("breach_id is not a usable id",),
            url=CATALOG_ROOT,
        )
    url = CATALOG_ROOT + breach_id
    payload, cache, warning = _fetch_json(
        url,
        None,
        ttl=_CATALOG_TTL,
        cache_factory=_catalog_cache,
        snapshot_var="CYBERAU_SPYCLOUD_CATALOG_SNAPSHOT",
    )
    if warning and payload is None:
        return _envelope(None, cache, warnings=(warning,), url=url)
    record = _catalog_record(payload or {})
    if not record:
        return _envelope(
            None,
            cache,
            warnings=("SpyCloud breach catalogue payload was not usable",),
            url=url,
        )
    normalised = _breach_payload(record, breach_id)
    if normalised is None:
        return _envelope(
            None,
            cache,
            warnings=("SpyCloud breach catalogue payload was not usable",),
            url=url,
        )
    return _envelope(normalised, cache, url=url)


def fetch_identifiers() -> tuple[list[dict], str, str]:
    """Read SpyCloud watchlist identifiers. Membership only, no verification secrets."""
    payload, cache, warning = _fetch_json(
        IDENTIFIERS_URL,
        None,
        ttl=_RECORD_TTL,
        cache_factory=_session_cache,
        snapshot_var="CYBERAU_SPYCLOUD_IDENTIFIERS_SNAPSHOT",
    )
    if warning and payload is None:
        return [], cache, warning
    rows = _result_rows(payload or {})
    if rows is None:
        return [], cache, warning or "SpyCloud watchlist payload was not usable"
    public = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        kept = {
            key: item.get(key)
            for key in ("identifier_name", "identifier_type", "status")
            if item.get(key) is not None
        }
        public.append(kept)
    return public, cache, warning


def watchlist_doctor(*, enabled: bool) -> str:
    gaps = None
    local = local_watchlist()
    if local is not None:
        identifiers, _cache, warning = fetch_identifiers()
        if identifiers and not warning:
            gaps = compare_watchlists(local, identifiers)
    return doctor_report(
        enabled=enabled,
        key_present=lookup("SPYCLOUD_API_KEY") is not None,
        gaps=gaps,
    )


class SpyCloudConnector(PremiumConnector):
    """SpyCloud exposure connector. Read-only, and off until the profile enables it."""

    def __init__(self) -> None:
        spec = get_vendor("spycloud")
        super().__init__(
            key="spycloud",
            server_name="spycloud",
            attribution=spec.terms.attribution,
            tools=[
                ToolSpec(
                    "spycloud_watchlist_exposure",
                    (
                        "Exposure records for watchlist domains since a date, "
                        "summarised by type and severity. Credential values are "
                        "redacted before return."
                    ),
                    spycloud_watchlist_exposure,
                ),
                ToolSpec(
                    "spycloud_breach_info",
                    (
                        "Metadata for one breach source: title, publish date, "
                        "record count, data classes."
                    ),
                    spycloud_breach_info,
                ),
            ],
            vendor=spec.server,
            licence_env=tuple(spec.licence_env),
            terms=spec.terms,
            quota=spec.quota,
        )

    def exposure_for(self, watchlist: Watchlist, since: date) -> list[ExposureFinding]:
        snapshot = os.environ.get("CYBERAU_SPYCLOUD_WATCHLIST_SNAPSHOT")
        offline = os.environ.get("CYBERAU_OFFLINE") == "1"
        if lookup("SPYCLOUD_API_KEY") is None and not snapshot and not offline:
            raise RuntimeError("SPYCLOUD_API_KEY is not set")
        findings, data, _cache, warnings = _collect_watchlist(
            since=since.isoformat(),
            watchlist_type=None,
            record_type=None,
            limit=1000,
        )
        if data is None:
            raise RuntimeError(warnings[0] if warnings else "unavailable")
        known = watchlist.known_subjects()
        return [item for item in findings if item.subject.value.casefold() in known]

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            watch = _schema_sample(
                "CYBERAU_SPYCLOUD_WATCHLIST_SNAPSHOT",
                _FIXTURES / "watchlist_synthetic.json",
            )
            problem = schema_drift(watch, kind="watchlist")
            if problem:
                return Probe(self.key, False, problem)
            catalog = _schema_sample(
                "CYBERAU_SPYCLOUD_CATALOG_SNAPSHOT",
                _FIXTURES / "breach_catalog_synthetic.json",
            )
            problem = schema_drift(catalog, kind="breach")
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        result = self.health_result(live=False)
        if not result.configured:
            return Probe(self.key, True, "not configured")
        if not live:
            return Probe(self.key, True, "offline ok")
        today = datetime.now(SYDNEY).date().isoformat()
        payload, _cache, warning = _fetch_json(
            WATCHLIST_URL,
            {"since": today},
            ttl=60,
            cache_factory=_session_cache,
            snapshot_var="CYBERAU_SPYCLOUD_WATCHLIST_SNAPSHOT",
            force_live=True,
        )
        if warning:
            return Probe(self.key, False, warning)
        if payload is None:
            return Probe(self.key, False, "live probe returned nothing")
        if check_schema:
            problem = schema_drift(payload, kind="watchlist")
            if problem:
                return Probe(self.key, False, problem)
        return Probe(self.key, True, "live ok")


def connector() -> SpyCloudConnector:
    return SpyCloudConnector()


register_connector("spycloud", connector)
