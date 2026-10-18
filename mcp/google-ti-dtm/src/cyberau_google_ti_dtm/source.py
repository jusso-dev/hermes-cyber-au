"""Read-only Google Threat Intelligence Digital Threat Monitoring connector.

Uses GTI_API_KEY. Do not reuse a VirusTotal Public API key. The server ships disabled.
"""

import hashlib
import json
import os
import re
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated, Literal
from zoneinfo import ZoneInfo

import httpx
import yaml
from cyberau_common import USER_AGENT
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Probe, ToolSpec, register_connector
from cyberau_common.snapshot import unavailable
from cyberau_premium.base import (
    ExposureFinding,
    PremiumConnector,
    Subject,
    Watchlist,
    finding_id,
)
from cyberau_premium.caching import cache_for_terms
from cyberau_premium.catalog import get_vendor
from cyberau_premium.present import finding_payload
from cyberau_premium.redact import redact_text
from cyberau_premium.store import ExposureStore
from jsonschema import Draft202012Validator
from pydantic import Field

ALERTS_URL = "https://www.virustotal.com/api/v3/dtm/alerts"
MONITORS_URL = "https://www.virustotal.com/api/v3/dtm/monitors"
X_TOOL = "jusso-dev.hermes-cyber-au.0.1"
PAGE_SIZE = 25
SOURCE = "gtidtm"
# Per-licence ceiling is not published. Stay at one request per second.
_RATE = 1.0
_BURST = 5
_SESSION_TTL = 3600
_SYDNEY = ZoneInfo("Australia/Sydney")
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE,
)
_LINK = re.compile(r"<([^>]+)>\s*;\s*([^,]+)")
_STATUS = re.compile(r"[A-Za-z0-9_-]{1,64}")
_PLAIN = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_SEVERITY = {"low", "medium", "high"}
_CREDENTIAL_KINDS = {"infostealer_credential", "breach_credential"}
_PACKAGE = Path(__file__).resolve().parents[2]
# Synthetic test copies. Only the offline schema check reads these, never a tool.
_FIXTURES = _PACKAGE / "tests" / "fixtures"
_CACHES: dict[str, object] = {}
_TRANSPORT = None
_RESOLVER = None
_SLEEPER = None
_RNG = None
_Date = Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")]
_Limit = Annotated[int, Field(ge=1, le=500)]
_Severity = Literal["low", "medium", "high"]

_MISSING_KEY = "GTI_API_KEY is not set"
_NOT_USABLE = "Google Threat Intelligence DTM response was not usable"
_UNAVAILABLE = "offline and nothing cached this session"
_LABEL = {
    "alerts": "Google Threat Intelligence DTM alerts",
    "monitors": "Google Threat Intelligence DTM monitors",
}
_RATE_LIMITED = "Google Threat Intelligence DTM returned HTTP 429 after Retry-After was honoured"


def gti_dtm_alerts(
    since: _Date | None = None,
    severity: _Severity | None = None,
    status: str | None = None,
    limit: _Limit = 50,
) -> dict:
    problem = _validate_alerts(since, severity, status, limit)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    records, findings, cache, warnings = _collect_alerts(
        since=since,
        severity=severity,
        status=status,
        limit=limit,
    )
    watch = _load_watchlist()
    if watch is not None and cache != "snapshot":
        _remember(findings, watch)
    stamps = [row["created_at"] for row in records if row.get("created_at")]
    return _envelope(
        records,
        cache,
        urls=[ALERTS_URL],
        warnings=tuple(warnings),
        data_as_of=max(stamps) if stamps else None,
    )


def gti_dtm_monitors() -> dict:
    records, cache, warnings = _collect_monitors()
    return _envelope(records, cache, urls=[MONITORS_URL], warnings=tuple(warnings))


def connector() -> PremiumConnector:
    spec = _spec()
    return GoogleTiDtmConnector(
        key="google-ti-dtm",
        server_name="gtidtm",
        attribution=spec.terms.attribution,
        tools=[
            ToolSpec(
                name="gti_dtm_alerts",
                description=(
                    "DTM alerts since a date, with monitor, severity, alert type and matched value."
                ),
                fn=gti_dtm_alerts,
            ),
            ToolSpec(
                name="gti_dtm_monitors",
                description="Configured monitors and what each watches.",
                fn=gti_dtm_monitors,
            ),
        ],
        vendor=spec.server,
        licence_env=tuple(spec.licence_env),
        terms=spec.terms,
        quota=spec.quota,
    )


class GoogleTiDtmConnector(PremiumConnector):
    def exposure_for(self, watchlist: Watchlist, since: date) -> list[ExposureFinding]:
        _records, findings, cache, _warnings = _collect_alerts(
            since=since.isoformat(),
            severity=None,
            status=None,
            limit=500,
        )
        if cache == "snapshot":
            # A snapshot or synthetic copy is not exposure evidence.
            return []
        matched = [
            finding
            for finding in findings
            if finding.subject.value.casefold() in watchlist.known_subjects()
        ]
        _remember(matched, watchlist)
        return matched

    def health(self, *, live: bool = False, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            problem = _schema_problem()
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        result = self.health_result(live=False)
        if not result.configured:
            if live:
                return Probe(self.key, False, _MISSING_KEY)
            return Probe(self.key, result.ok, result.detail)
        if not live:
            return Probe(self.key, True, "offline ok")
        problem = _live_problem()
        if problem:
            return Probe(self.key, False, problem)
        return Probe(self.key, True, "live ok")


def schema_drift(payload: object, kind: str = "alerts") -> str | None:
    """Return a drift message when a vendor payload no longer matches the schema."""
    if not isinstance(payload, dict):
        return _NOT_USABLE
    schema = json.loads(_response_schema_path(kind).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors = list(validator.iter_errors(payload))
    if not errors:
        return None
    error = min(errors, key=lambda item: (list(item.path), item.message))
    match = re.search(r"'([^']+)'", error.message)
    name = match.group(1) if match else error.message
    where = ".".join(str(part) for part in error.path)
    label = f"{where}.{name}" if where else name
    return f"Google Threat Intelligence DTM schema drift, missing {label}"


def _collect_alerts(
    *,
    since: str | None,
    severity: str | None,
    status: str | None,
    limit: int,
) -> tuple[list[dict], list[ExposureFinding], str, list[str]]:
    params = {
        "size": str(min(limit, PAGE_SIZE)),
        "order": "desc",
        "sort": "created_at",
    }
    if since:
        params["since"] = _since_rfc3339(since)
    if severity:
        params["severity"] = severity
    if status:
        params["status"] = status
    rows, cache, warnings = _collect(
        "alerts",
        ALERTS_URL,
        params,
        limit=limit,
        collection="alerts",
    )
    records: list[dict] = []
    findings: list[ExposureFinding] = []
    kept = 0
    for alert in rows:
        if not _keep_alert(alert, since=since, severity=severity, status=status):
            continue
        if kept >= limit:
            break
        try:
            record, finding = _alert_record(alert)
        except (TypeError, ValueError):
            warnings.append(_NOT_USABLE)
            continue
        records.append(record)
        if finding is not None:
            findings.append(finding)
        kept += 1
    return records, findings, cache, warnings


def _collect_monitors() -> tuple[list[dict], str, list[str]]:
    params = {"size": str(PAGE_SIZE), "order": "desc", "sort": "created_at"}
    rows, cache, warnings = _collect(
        "monitors",
        MONITORS_URL,
        params,
        limit=PAGE_SIZE * _spec().max_pages,
        collection="monitors",
    )
    records = []
    for monitor in rows:
        if not isinstance(monitor, dict):
            warnings.append(_NOT_USABLE)
            continue
        records.append(_monitor_record(monitor))
    return records, cache, warnings


def _collect(
    kind: str,
    url: str,
    params: dict[str, str] | None,
    *,
    limit: int,
    collection: str,
) -> tuple[list[dict], str, list[str]]:
    rows: list[dict] = []
    warnings: list[str] = []
    cache = "snapshot"
    labels: list[str] = []
    snapshot_served = False
    current = url
    query: dict[str, str] | None = params
    seen: set[str] = set()
    for _page in range(_spec().max_pages):
        if current in seen:
            break
        seen.add(current)
        payload, cache, warning, headers, _status = _fetch_one(kind, current, query)
        if warning or payload is None:
            reason = warning or _NOT_USABLE
            warnings.append(reason if rows else unavailable(_LABEL[kind], reason))
            break
        problem = schema_drift(payload, kind=kind)
        if problem:
            warnings.append(problem)
            break
        batch = payload.get(collection) or []
        if not isinstance(batch, list):
            warnings.append(_NOT_USABLE)
            break
        labels.append(cache)
        snapshot_served = snapshot_served or cache == "snapshot"
        rows.extend(item for item in batch if isinstance(item, dict))
        if len(rows) >= limit:
            break
        nxt = _next_link(headers)
        if not nxt:
            break
        current = str(httpx.URL(current).join(nxt))
        query = None
    if snapshot_served:
        warnings.append(_snapshot_note(kind))
    for label in ("snapshot", "stale", "miss", "hit"):
        if label in labels:
            cache = label
            break
    return rows[:limit], cache, warnings


def _fetch_one(
    kind: str,
    url: str,
    params: dict[str, str] | None,
    *,
    force_live: bool = False,
) -> tuple[dict | None, str, str, dict, int]:
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    pinned = bool(os.environ.get(_snapshot_env(kind)))
    cache = _session_cache()
    key = cache.key("GET", url, params, b"", _scope())
    if not force_live and not pinned:
        cached = cache.get(key)
        if cached and cache.fresh(cached):
            return _load_body(cached.body), "hit", "", dict(cached.headers), 200
    if not force_live and (offline or pinned):
        return _from_snapshot(kind, cache, key, pinned=pinned)
    headers = _auth_headers()
    if headers is None:
        return None, "snapshot", _MISSING_KEY, {}, 0
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist_path())))
    policy_kwargs = {}
    if _RESOLVER is not None:
        policy_kwargs["resolver"] = _RESOLVER
    client = HttpClient(
        "google-ti-dtm",
        policy=EgressPolicy(allowlist, "google-ti-dtm", **policy_kwargs),
        cache=cache,
        limiter=RateLimiter(_root() / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=_RATE,
        burst=_BURST,
        window="rolling",
        timeout=30,
        retries=1,
        auth_scope=_scope(),
        transport=_TRANSPORT,
        sleeper=_SLEEPER,
        rng=_RNG,
    )
    try:
        response = client.get(
            url,
            params=params,
            headers=headers,
            ttl=_SESSION_TTL,
            skip_cache=force_live,
        )
    except (HttpError, EgressDenied, TimeoutError) as exc:
        if not force_live:
            cached = cache.get(key)
            if cached:
                return _load_body(cached.body), "stale", "", dict(cached.headers), 200
        return None, "snapshot", _safe(str(exc)) or _UNAVAILABLE, {}, 0
    finally:
        client.close()
    if response.status in (401, 403):
        return None, response.cache, _auth_warning(response.status), {}, response.status
    if response.status == 429:
        cached = None if force_live else cache.get(key)
        if cached:
            return _load_body(cached.body), "stale", "", dict(cached.headers), 200
        return None, "snapshot", _RATE_LIMITED, {}, 429
    if response.status >= 400:
        return None, response.cache, f"upstream status {response.status}", {}, response.status
    payload = _load_body(response.body)
    if payload is None:
        return None, response.cache, _NOT_USABLE, response.headers, response.status
    return payload, response.cache, "", response.headers, response.status


def _from_snapshot(
    kind: str, cache, key: str, *, pinned: bool
) -> tuple[dict | None, str, str, dict, int]:
    if not pinned:
        # A real response kept for this session beats the shipped synthetic copy.
        cached = cache.get(key)
        if cached:
            return _load_body(cached.body), "stale", "", dict(cached.headers), 200
    path = _snapshot_path(kind)
    if path is not None and path.is_file():
        payload = _read_json(path)
        if payload is None:
            return None, "snapshot", _NOT_USABLE, {}, 0
        return payload, "snapshot", "", {}, 200
    return None, "snapshot", _UNAVAILABLE, {}, 0


def _live_problem() -> str | None:
    checks = (
        ("alerts", ALERTS_URL, {"size": "1"}),
        ("monitors", MONITORS_URL, {"size": "1"}),
    )
    for kind, url, params in checks:
        payload, _cache, warning, _headers, status = _fetch_one(
            kind,
            url,
            params,
            force_live=True,
        )
        if warning:
            return warning
        if status >= 400:
            return f"upstream status {status}"
        problem = schema_drift(payload, kind=kind)
        if problem:
            return problem
    return None


def _schema_problem() -> str | None:
    """Offline schema check. Reads the operator snapshot, else the test fixture."""
    for kind in ("alerts", "monitors"):
        path = _snapshot_path(kind) or _FIXTURES / f"dtm_{kind}_synthetic.json"
        if not path.is_file():
            continue
        payload = _read_json(path)
        if payload is None:
            return f"Google Threat Intelligence DTM {kind} snapshot was not usable"
        problem = schema_drift(payload, kind=kind)
        if problem:
            return problem
    return None


def _alert_record(alert: dict) -> tuple[dict, ExposureFinding | None]:
    created = str(alert.get("created_at") or "")
    _parse_time(created)
    matched = _matched_values(alert)
    subject_text = matched[0] if matched else ""
    finding = None
    if subject_text and created:
        finding = _finding(alert, subject_text, created)
    record = {
        "id": _token(alert.get("id")),
        "monitor_id": _token(alert.get("monitor_id")),
        "severity": _token(str(alert.get("severity") or "").casefold()),
        "status": _token(alert.get("status")),
        "alert_type": _token(alert.get("alert_type")),
        "created_at": created,
        "title": _wrap(alert.get("title")),
        "summary": _wrap(alert.get("alert_summary")),
        "matched_value": _wrap(subject_text),
        "finding": None if finding is None else finding_payload(finding),
    }
    return record, finding


def _finding(alert: dict, subject_text: str, created: str) -> ExposureFinding:
    kind = _kind(str(alert.get("alert_type") or ""))
    subject, personal = _subject(subject_text)
    observed = _parse_time(created)
    confidence = "unverified_claim" if kind == "leak_site_claim" else "vendor_reported"
    scope = "store_metadata"
    if _spec().terms.store == "full":
        scope = "store_full"
    elif _spec().terms.store == "none":
        scope = "session_only"
    source_ref = str(alert.get("id") or "")
    return ExposureFinding(
        finding_id=finding_id("gtidtm", kind, subject.value, source_ref),
        vendor="gtidtm",
        kind=kind,
        subject=subject,
        observed_at=observed,
        first_seen=observed,
        licence_scope=scope,
        confidence=confidence,
        counts={"alerts": 1},
        data_classes=["credential"] if kind in _CREDENTIAL_KINDS else ["domain"],
        source_ref=source_ref,
        stix_exportable=False,
        contains_personal_information=personal or kind in _CREDENTIAL_KINDS,
    )


def _monitor_record(monitor: dict) -> dict:
    watches = [_wrap(value) for value in _watch_values(monitor)]
    return {
        "id": _token(monitor.get("id")),
        "name": _wrap(monitor.get("name")),
        "description": _wrap(monitor.get("description")),
        "enabled": bool(monitor.get("enabled")),
        "watches": [item for item in watches if item],
    }


def _keep_alert(
    alert: dict,
    *,
    since: str | None,
    severity: str | None,
    status: str | None,
) -> bool:
    if severity and str(alert.get("severity") or "").casefold() != severity:
        return False
    if status and str(alert.get("status") or "").casefold() != status.casefold():
        return False
    if since:
        created = alert.get("created_at")
        if not isinstance(created, str):
            return False
        observed = _parse_time(created)
        if _sydney_day(observed) < since:
            return False
    return True


def _matched_values(alert: dict) -> list[str]:
    found: list[str] = []
    for key in ("topic_matches", "doc_matches", "label_matches"):
        for item in alert.get(key) or []:
            if isinstance(item, str) and item.strip():
                found.append(item.strip())
            elif isinstance(item, dict):
                found.extend(_strings_from(item))
    return found


def _strings_from(item: dict) -> list[str]:
    found = []
    for name in ("value", "match_value", "keyword"):
        raw = item.get(name)
        if isinstance(raw, str) and raw.strip():
            found.append(raw.strip())
    topic = item.get("topic")
    if isinstance(topic, dict):
        raw = topic.get("value")
        if isinstance(raw, str) and raw.strip():
            found.append(raw.strip())
    return found


def _watch_values(monitor: dict) -> list[str]:
    topics = monitor.get("topics") or monitor.get("conditions") or []
    if isinstance(topics, dict):
        topics = [topics]
    found: list[str] = []
    for topic in topics:
        if isinstance(topic, str) and topic.strip():
            found.append(topic.strip())
        elif isinstance(topic, dict):
            found.extend(_strings_from(topic))
    if found:
        return found
    description = monitor.get("description")
    if isinstance(description, str) and description.strip():
        return [description.strip()]
    return []


def _subject(value: str) -> tuple[Subject, bool]:
    text = value.strip()
    if "@" in text:
        domain = text.rsplit("@", 1)[-1].strip().lower().rstrip(".")
        return Subject(type="email_domain", value=domain), True
    if _DOMAIN.match(text):
        return Subject(type="domain", value=text.lower().rstrip(".")), False
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", text):
        return Subject(type="ip", value=text), False
    return Subject(type="brand", value=text), False


def _kind(alert_type: str) -> str:
    text = alert_type.casefold().replace("-", "_").replace(" ", "_")
    if "infostealer" in text or "stealer" in text:
        return "infostealer_credential"
    if "credential" in text:
        return "breach_credential"
    if "ransomware" in text or "leak_site" in text:
        return "leak_site_claim"
    if "leak" in text:
        return "data_leak_disclosure"
    if "typosquat" in text or "lookalike" in text:
        return "typosquat_domain"
    if "impersonat" in text or "brand" in text:
        return "brand_impersonation"
    if "attack_surface" in text or text == "asm":
        return "attack_surface_issue"
    return "dark_web_mention"


def _validate_alerts(
    since: str | None,
    severity: str | None,
    status: str | None,
    limit: int,
) -> str | None:
    if since is not None:
        if not isinstance(since, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", since):
            return "since must be YYYY-MM-DD in Australia/Sydney"
        try:
            datetime.strptime(since, "%Y-%m-%d")
        except ValueError:
            return "since must be YYYY-MM-DD in Australia/Sydney"
    if severity is not None and severity not in _SEVERITY:
        return "severity must be low, medium or high"
    if status is not None and (not isinstance(status, str) or not _STATUS.fullmatch(status)):
        return "status must be a short token"
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        return "limit must be an integer from 1 to 500"
    return None


def _since_rfc3339(since: str) -> str:
    parsed = datetime.strptime(since, "%Y-%m-%d")
    local = datetime(parsed.year, parsed.month, parsed.day, tzinfo=_SYDNEY)
    return local.isoformat()


def _parse_time(value: str) -> datetime:
    moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def _sydney_day(moment: datetime) -> str:
    return moment.astimezone(_SYDNEY).date().isoformat()


def _next_link(headers: dict) -> str | None:
    raw = ""
    for key, value in headers.items():
        if str(key).lower() == "link":
            raw = str(value)
            break
    for match in _LINK.finditer(raw):
        if re.search(r'rel="?next"?', match.group(2), re.IGNORECASE):
            return match.group(1)
    return None


def _wrap(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""
    return untrusted_text(redact_text(value), SOURCE)


def _token(value: object) -> str:
    """Return a plain identifier as is. Anything else is feed text, so wrap it."""
    if value is None or value == "":
        return ""
    text = str(value)
    if _PLAIN.fullmatch(text):
        return text
    return _wrap(text)


def _envelope(
    data,
    cache: str,
    *,
    urls: list[str] | None = None,
    warnings: tuple[str, ...] = (),
    data_as_of: str | None = None,
) -> dict:
    return envelope(
        SOURCE,
        data,
        urls=urls or [],
        cache=cache,
        data_as_of=data_as_of,
        warnings=tuple(_safe(item) for item in warnings),
        attribution=_spec().terms.attribution,
    )


def _remember(findings: list[ExposureFinding], watchlist: Watchlist) -> None:
    if not findings:
        return
    store = ExposureStore(_root() / "intel.sqlite")
    terms = _spec().terms
    for finding in findings:
        store.write(finding, terms=terms, watchlist=watchlist)


def _load_watchlist() -> Watchlist | None:
    raw = os.environ.get("CYBERAU_DATA_DIR")
    if not raw:
        return None
    path = Path(raw) / "watchlists" / "org-exposure.yaml"
    if not path.is_file():
        return None
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(loaded, dict):
        return None
    return Watchlist.model_validate(loaded)


def _auth_headers() -> dict[str, str] | None:
    secret = lookup("GTI_API_KEY")
    if secret is None:
        return None
    return {"x-apikey": secret, "x-tool": X_TOOL}


def _auth_warning(status: int) -> str:
    return (
        f"GTI_API_KEY was rejected with HTTP {status}. "
        "Set a Google Threat Intelligence key with DTM entitlement. "
        "Do not reuse a VirusTotal Public API key."
    )


def _safe(message: str) -> str:
    cleaned = redact(message)
    secret = lookup("GTI_API_KEY")
    if secret and secret in cleaned:
        cleaned = cleaned.replace(secret, "[REDACTED]")
    return cleaned


def _scope() -> str:
    secret = lookup("GTI_API_KEY")
    if secret is None:
        return "anonymous"
    return hashlib.sha256(secret.encode()).hexdigest()[:16]


def _session_cache():
    root = _root()
    identity = f"{root}|{_scope()}"
    cache = _CACHES.get(identity)
    if cache is None:
        cache = cache_for_terms(root / "http_cache.sqlite", _spec().terms)
        _CACHES[identity] = cache
    return cache


def _root() -> Path:
    raw = os.environ.get("CYBERAU_DATA_DIR")
    if raw:
        return Path(raw)
    return Path("/tmp") / "cyberau-gtidtm"


def _snapshot_env(kind: str) -> str:
    if kind == "alerts":
        return "CYBERAU_GTI_DTM_ALERTS"
    return "CYBERAU_GTI_DTM_MONITORS"


def _snapshot_path(kind: str) -> Path | None:
    """Operator-supplied snapshot file, or None. Nothing shipped is ever served."""
    raw = os.environ.get(_snapshot_env(kind))
    return Path(raw) if raw else None


def _snapshot_note(kind: str) -> str:
    return (
        f"Served from the operator-supplied snapshot file in {_snapshot_env(kind)}, "
        "not live Google Threat Intelligence DTM data. Do not treat it as current."
    )


def _response_schema_path(kind: str) -> Path:
    return _PACKAGE / "schema" / f"gti_dtm_{kind}.response.json"


def _allowlist_path() -> Path:
    return _PACKAGE.parent / "egress-allowlist.yaml"


def _read_json(path: Path) -> dict | None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    return _load_body(text.encode("utf-8"))


def _load_body(body: bytes) -> dict | None:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _spec():
    return get_vendor("gtidtm")


register_connector("google-ti-dtm", connector)
