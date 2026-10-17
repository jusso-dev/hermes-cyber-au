"""Read-only Intel 471 Titan alerts. Watchers are not created or edited."""

import base64
import hashlib
import json
import os
import re
from collections import Counter
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import yaml
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimited, RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Probe, ToolSpec, register_connector
from cyberau_premium.base import (
    ExposureFinding,
    PremiumConnector,
    Subject,
    Watchlist,
    finding_id,
)
from cyberau_premium.caching import cache_for_terms
from cyberau_premium.catalog import get_vendor
from cyberau_premium.paths import data_dir
from cyberau_premium.store import ExposureStore
from jsonschema import Draft202012Validator
from pydantic import Field, ValidationError

_API = "https://api.intel471.com/v1"
_ALERTS = f"{_API}/alerts"
_BREACH = f"{_API}/breachAlerts"
_CREDENTIALS = f"{_API}/credentials/occurrences"
_SYDNEY = ZoneInfo("Australia/Sydney")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_UID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_PACKAGE = Path(__file__).resolve().parents[2]
# Titan does not publish a quota. Stay slow and honour Retry-After on 429.
_RATE = 4.0
_BURST = 8
_READ_PATHS = {
    "/v1/alerts",
    "/v1/breachAlerts",
    "/v1/credentials",
    "/v1/credentials/occurrences",
    "/v1/credentialSets",
}
_SOURCE_FIELDS = (
    ("breachAlert", "breach_alert"),
    ("breach_alert", "breach_alert"),
    ("credential_occurrence", "credential_occurrence"),
    ("credential", "credential"),
    ("credential_set", "credential_set"),
    ("data_leak_post", "data_leak"),
    ("instantMessage", "instant_message"),
    ("privateMessage", "private_message"),
    ("cveReport", "cve_report"),
    ("post", "post"),
    ("report", "report"),
    ("indicator", "indicator"),
    ("entity", "entity"),
    ("event", "event"),
    ("actor", "actor"),
)
_KINDS = {
    "breach_alert": "data_leak_disclosure",
    "credential": "breach_credential",
    "credential_set": "breach_credential",
    "credential_occurrence": "infostealer_credential",
    "data_leak": "data_leak_disclosure",
}
_AFFILIATION = {
    "my_employees": "employees",
    "vip_emails": "vip_emails",
    "my_customers": "customers",
    "third_parties": "third_parties",
}
_SNAPSHOTS = {
    "alerts": "alerts_synthetic.json",
    "breach": "breach_alerts_synthetic.json",
    "credentials": "credentials_occurrences_synthetic.json",
}
_Date = Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")]
_Limit = Annotated[int, Field(ge=1, le=1000)]
_Query = Annotated[str, Field(min_length=2)]
_Domain = Annotated[str, Field(min_length=1)]

# Test seams. Production leaves them unset.
_TRANSPORT = None
_SLEEPER = None
_RNG = None
_CACHE = None
_CACHE_PATH: Path | None = None


def intel471_watcher_alerts(
    since: _Date | None = None,
    watcher_group: str | None = None,
    limit: _Limit = 100,
) -> dict:
    """Recent watcher alerts with watcher name, source type and timestamp."""
    problem = _check_limit(limit)
    if problem:
        return _envelope([], "snapshot", (), (problem,))
    problem = _check_since(since)
    if problem:
        return _envelope([], "snapshot", (), (problem,))
    watchlist, trouble = _load_watchlist()
    if trouble or watchlist is None:
        message = trouble or "org-exposure watchlist is not configured"
        return _envelope([], "snapshot", (), (message,))
    records, cache, warning = _watcher_records(watchlist, since, watcher_group, limit)
    if warning:
        return _envelope([], cache, (_ALERTS,), (warning,))
    return _envelope(records, cache, (_ALERTS,), _origin_notes(cache))


def intel471_breach_alerts(query: _Query, since: _Date | None = None) -> dict:
    """Breach alerts mentioning watchlist names or domains."""
    problem = _check_query(query)
    if problem:
        return _envelope([], "snapshot", (), (problem,))
    problem = _check_since(since)
    if problem:
        return _envelope([], "snapshot", (), (problem,))
    watchlist, trouble = _load_watchlist()
    if trouble or watchlist is None:
        message = trouble or "org-exposure watchlist is not configured"
        return _envelope([], "snapshot", (), (message,))
    allowed = _allowed_query(query, watchlist)
    if allowed is None:
        return _envelope(
            [],
            "snapshot",
            (),
            ("That name is not on the org-exposure watchlist, so it was not sent to Intel 471.",),
        )
    records, cache, warning = _breach_records(watchlist, allowed, since)
    if warning:
        return _envelope([], cache, (_BREACH,), (warning,))
    return _envelope(records, cache, (_BREACH,), _origin_notes(cache))


def intel471_credential_exposure(domain: _Domain, since: _Date | None = None) -> dict:
    """Credential occurrences for a watchlist domain, as counts."""
    problem = _check_domain(domain)
    if problem:
        return _envelope([], "snapshot", (), (problem,))
    problem = _check_since(since)
    if problem:
        return _envelope([], "snapshot", (), (problem,))
    watchlist, trouble = _load_watchlist()
    if trouble or watchlist is None:
        message = trouble or "org-exposure watchlist is not configured"
        return _envelope([], "snapshot", (), (message,))
    allowed = _allowed_domain(domain, watchlist)
    if allowed is None:
        return _envelope(
            [],
            "snapshot",
            (),
            ("That domain is not on the org-exposure watchlist, so it was not sent to Intel 471.",),
        )
    records, cache, warning = _credential_records(watchlist, allowed, since)
    if warning:
        return _envelope([], cache, (_CREDENTIALS,), (warning,))
    return _envelope(records, cache, (_CREDENTIALS,), _origin_notes(cache))


class Intel471Connector(PremiumConnector):
    """Paid Titan connector. The shared premium package still does not call Intel 471."""

    def __init__(self) -> None:
        spec = get_vendor("intel471")
        super().__init__(
            key="intel471",
            server_name="intel471",
            attribution=spec.terms.attribution,
            tools=[
                ToolSpec(
                    "intel471_watcher_alerts",
                    "Recent watcher alerts with watcher name, source type and timestamp.",
                    intel471_watcher_alerts,
                ),
                ToolSpec(
                    "intel471_breach_alerts",
                    "Breach alerts mentioning watchlist names or domains.",
                    intel471_breach_alerts,
                ),
                ToolSpec(
                    "intel471_credential_exposure",
                    "Credential occurrences for a watchlist domain, as counts.",
                    intel471_credential_exposure,
                ),
            ],
            vendor=spec.server,
            licence_env=tuple(spec.licence_env),
            terms=spec.terms,
            quota=spec.quota,
        )

    def exposure_for(self, watchlist: Watchlist, since: date) -> list[ExposureFinding]:
        day = since.isoformat()
        findings: list[ExposureFinding] = []
        groups = (
            _watcher_records(watchlist, day, None, 100),
            _breach_records(watchlist, None, day),
            _credential_records(watchlist, None, day),
        )
        for records, _cache, warning in groups:
            if warning or not records:
                continue
            for record in records:
                findings.append(ExposureFinding.model_validate(record["finding"]))
        return findings

    def health(self, *, live: bool = False, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            payload = _load(_schema_text())
            problem = schema_drift(payload or {})
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        result = self.health_result(live=False)
        if not result.configured:
            if live:
                missing = ", ".join(name for name in self.licence_env if lookup(name) is None)
                return Probe(self.key, False, f"not configured: set {missing}")
            return Probe(self.key, result.ok, result.detail)
        if not live:
            return Probe(self.key, True, "offline ok")
        watchlist, _trouble = _load_watchlist()
        domain = _first_domain(watchlist)
        probes = [("alerts", _ALERTS, {"count": "1", "markAsRead": "false", "showRead": "true"})]
        if domain:
            probes.append(("breach", _BREACH, {"count": "1", "breachAlert": domain}))
            probes.append(("credentials", _CREDENTIALS, {"count": "1", "domain": domain}))
        for kind, url, params in probes:
            payload, cache, warning = _fetch(kind, url, params, force_live=True)
            if warning:
                return Probe(self.key, False, warning)
            if cache != "miss":
                return Probe(self.key, False, f"{kind} check was answered from {cache}, not live")
            problem = schema_drift(payload or {})
            if problem:
                return Probe(self.key, False, problem)
        if not domain:
            return Probe(
                self.key,
                True,
                "live ok (alerts only: no watchlist domain to probe breach alerts and credentials)",
            )
        return Probe(self.key, True, "live ok")


def schema_drift(payload: dict) -> str | None:
    """Return a drift message when a documented field has been renamed or dropped."""
    if not isinstance(payload, dict):
        return "Intel 471 payload was not an object"
    if "breach_alerts" in payload or "breach_alerts_total_count" in payload:
        return _drift_rows(payload, "breach_alerts", ("uid",))
    if "credential_occurrences" in payload or "credential_occurrences_total_count" in payload:
        if "credential_occurrences_total_count" not in payload:
            return "Intel 471 schema drift, missing credential_occurrences_total_count"
        if not isinstance(payload.get("credential_occurrences_total_count"), int):
            return "Intel 471 credential count was not usable"
        rows = payload.get("credential_occurrences")
        if rows is None:
            return None
        return _drift_rows(payload, "credential_occurrences", ("uid",))
    if "alerts" not in payload and "alertTotalCount" not in payload:
        return "Intel 471 schema drift, missing alerts"
    return _drift_rows(payload, "alerts", ("uid",), any_of=(("foundTime", "found_time"),))


def _watcher_records(
    watchlist: Watchlist,
    since: str | None,
    watcher_group: str | None,
    limit: int,
    *,
    force_live: bool = False,
) -> tuple[list[dict], str, str]:
    payload, cache, warning = _collect_alerts(since, watcher_group, limit, force_live=force_live)
    if warning:
        return [], cache, warning
    problem = schema_drift(payload or {})
    if problem:
        return [], cache, problem
    groups = _group_index(payload or {})
    records = []
    for item in (payload or {}).get("alerts") or []:
        if not isinstance(item, dict):
            return [], cache, "Intel 471 alerts payload was not usable"
        record = _alert_record(item, groups, watchlist, since, watcher_group)
        if record:
            records.append(record)
        if len(records) >= limit:
            break
    problem = _check_records("intel471_watcher_alerts", records)
    if problem:
        return [], cache, problem
    return records, cache, ""


def _breach_records(
    watchlist: Watchlist,
    query: str | None,
    since: str | None,
) -> tuple[list[dict], str, str]:
    subjects = _search_texts(watchlist, query)
    if not subjects:
        return [], "snapshot", ""
    merged: list[dict] = []
    groups_seen: list[dict] = []
    cache = "snapshot"
    for text in subjects:
        params: dict[str, str] = {"breachAlert": text, "count": "100", "sort": "latest"}
        start = _from_value(since)
        if start:
            params["from"] = start
        payload, cache, warning = _fetch("breach", _BREACH, params)
        if warning:
            return [], cache, warning
        problem = schema_drift(payload or {})
        if problem:
            return [], cache, problem
        for item in (payload or {}).get("breach_alerts") or []:
            if isinstance(item, dict):
                groups_seen.append(item)
    seen: set[str] = set()
    for item in groups_seen:
        record = _breach_record(item, watchlist, since)
        if record is None or record["uid"] in seen:
            continue
        seen.add(record["uid"])
        merged.append(record)
    problem = _check_records("intel471_breach_alerts", merged)
    if problem:
        return [], cache, problem
    return merged, cache, ""


def _credential_records(
    watchlist: Watchlist,
    domain: str | None,
    since: str | None,
) -> tuple[list[dict], str, str]:
    domains = [domain] if domain else _domain_values(watchlist)
    records = []
    cache = "snapshot"
    for name in domains:
        params = {"domain": name, "count": "100", "sort": "latest"}
        start = _from_value(since)
        if start:
            params["from"] = start
        payload, cache, warning = _fetch("credentials", _CREDENTIALS, params)
        if warning:
            return [], cache, warning
        problem = schema_drift(payload or {})
        if problem:
            return [], cache, problem
        record = _credential_record(payload or {}, watchlist, name, since)
        if record:
            records.append(record)
    problem = _check_records("intel471_credential_exposure", records)
    if problem:
        return [], cache, problem
    return records, cache, ""


def _collect_alerts(
    since: str | None,
    watcher_group: str | None,
    limit: int,
    *,
    force_live: bool,
) -> tuple[dict | None, str, str]:
    per_page = 1 if force_live else min(100, limit)
    needed = max(1, (limit + 99) // 100)
    pages = 1 if force_live or _snapshot_active() else min(_max_pages(), needed)
    offset = None
    alerts: list = []
    groups: list = []
    cache = "snapshot"
    for _page in range(pages):
        params = {
            "count": str(per_page),
            "markAsRead": "false",
            "showRead": "true",
            "displayWatchers": "true",
            "sort": "latest",
        }
        start = _from_value(since)
        if start:
            params["from"] = start
        if watcher_group:
            params["watcherGroup"] = watcher_group
        if offset:
            params["offset"] = offset
        payload, cache, warning = _fetch("alerts", _ALERTS, params, force_live=force_live)
        if warning:
            return None, cache, warning
        problem = schema_drift(payload or {})
        if problem:
            return None, cache, problem
        rows = (payload or {}).get("alerts") or []
        if not isinstance(rows, list):
            return None, cache, "Intel 471 alerts payload was not usable"
        alerts.extend(rows)
        groups.extend((payload or {}).get("watcherGroups") or [])
        if len(rows) < per_page:
            break
        last = rows[-1].get("uid") if isinstance(rows[-1], dict) else None
        if not last or last == offset:
            break
        offset = str(last)
    return {"alerts": alerts, "watcherGroups": groups}, cache, ""


def _alert_record(
    item: dict,
    groups: dict[str, dict],
    watchlist: Watchlist,
    since: str | None,
    watcher_group: str | None,
) -> dict | None:
    moment = _moment(item)
    if moment is None or not _on_or_after(moment, since):
        return None
    name = _watcher_name(item, groups)
    if watcher_group and not _group_selected(item, name, watcher_group):
        return None
    subject_value = _match_any(_alert_candidates(item, groups), watchlist)
    if subject_value is None:
        return None
    uid = _uid(item)
    if not uid:
        return None
    source_type = _source_type(item)
    finding = _finding(
        watchlist,
        kind=_KINDS.get(source_type, "dark_web_mention"),
        subject_value=subject_value,
        observed=moment,
        source_ref=uid,
        personal=False,
        data_classes=["watcher alert"],
    )
    _remember(finding, watchlist)
    return {
        "uid": uid,
        "watcher_name": untrusted_text(name, "intel471"),
        "source_type": source_type,
        "observed_at": _iso(moment),
        "finding": _public_finding(finding),
    }


def _breach_record(item: dict, watchlist: Watchlist, since: str | None) -> dict | None:
    moment = _moment(item)
    if moment is None or not _on_or_after(moment, since):
        return None
    subject_value = _match_any(_breach_candidates(item), watchlist)
    if subject_value is None:
        return None
    uid = _uid(item)
    if not uid:
        return None
    victim = _victim_name(item)
    title = _breach_title(item)
    finding = _finding(
        watchlist,
        kind="data_leak_disclosure",
        subject_value=subject_value,
        observed=moment,
        source_ref=uid,
        personal=bool(victim),
        data_classes=["breach alert"],
    )
    # A watchlist entry spelt like the victim would put the name in the store as the subject.
    if subject_value.casefold() != victim.casefold():
        _remember(finding, watchlist)
    record = {
        "uid": uid,
        "observed_at": _iso(moment),
        "title": untrusted_text(title, "intel471"),
        "stays_in_profile": True,
        "finding": _public_finding(finding),
    }
    # The name is for this profile session only. The metadata store keeps the uid.
    if victim:
        record["victim"] = untrusted_text(victim, "intel471")
    return record


def _credential_record(
    payload: dict,
    watchlist: Watchlist,
    domain: str,
    since: str | None,
) -> dict | None:
    total = payload.get("credential_occurrences_total_count")
    if not isinstance(total, int):
        return None
    rows = payload.get("credential_occurrences") or []
    if not isinstance(rows, list):
        return None
    if total == 0:
        return None
    moments = [
        moment for row in rows if isinstance(row, dict) for moment in (_moment(row),) if moment
    ]
    observed = max(moments) if moments else datetime.now(UTC)
    if since and moments and not any(_on_or_after(moment, since) for moment in moments):
        return None
    counts: dict[str, int] = {"occurrences": total}
    if total == len(rows):
        affiliations: Counter[str] = Counter()
        for row in rows:
            if not isinstance(row, dict):
                continue
            credential = _credential_body(row)
            row_domain = str(
                credential.get("credential_domain") or credential.get("detection_domain") or domain
            )
            if row_domain.casefold() != domain.casefold():
                continue
            for item in credential.get("affiliations") or []:
                mapped = _AFFILIATION.get(str(item))
                if mapped:
                    affiliations[mapped] += 1
        for name, value in sorted(affiliations.items()):
            if value:
                counts[name] = value
    kind = "breach_credential"
    if any(isinstance(row, dict) and _malware(row) for row in rows):
        kind = "infostealer_credential"
    finding = _finding(
        watchlist,
        kind=kind,
        subject_value=domain,
        observed=observed,
        source_ref=f"credentials:{domain}",
        personal=True,
        counts=counts,
        data_classes=["credential count"],
    )
    _remember(finding, watchlist)
    return {
        "domain": domain,
        "observed_at": _iso(observed),
        "counts": counts,
        "finding": _public_finding(finding),
    }


def _finding(
    watchlist: Watchlist,
    *,
    kind: str,
    subject_value: str,
    observed: datetime,
    source_ref: str,
    personal: bool,
    data_classes: list[str],
    counts: dict[str, int] | None = None,
) -> ExposureFinding:
    subject = _subject(subject_value, watchlist)
    return ExposureFinding(
        finding_id=finding_id("intel471", kind, subject.value, source_ref),
        vendor="intel471",
        kind=kind,
        subject=subject,
        observed_at=observed,
        first_seen=observed,
        licence_scope="store_metadata",
        confidence="vendor_reported",
        counts=counts,
        data_classes=data_classes,
        source_ref=source_ref,
        stix_exportable=False,
        contains_personal_information=personal,
    )


def _public_finding(finding: ExposureFinding) -> dict:
    return finding.model_dump(mode="json", exclude_none=True)


def _remember(finding: ExposureFinding, watchlist: Watchlist) -> None:
    if _snapshot_active():
        # A snapshot is a fixture, not an observation. It never becomes history.
        return
    store = ExposureStore(_data_root() / "intel.sqlite")
    store.write(finding, terms=_terms(), watchlist=watchlist)


def _fetch(
    kind: str,
    url: str,
    params: dict[str, str],
    *,
    force_live: bool = False,
) -> tuple[dict | None, str, str]:
    blocked = _guard_request(url, params)
    if blocked:
        return None, "snapshot", blocked
    if not force_live:
        body = _snapshot_body(kind)
        if body is not None:
            payload = _load(body)
            if payload is None:
                return None, "snapshot", "Intel 471 payload was not usable"
            return payload, "snapshot", ""
        if os.environ.get("CYBERAU_INTEL471_SNAPSHOT"):
            return None, "snapshot", "Intel 471 snapshot was not usable"
    if not _configured():
        return (
            None,
            "snapshot",
            ("Intel 471 is not configured. Set INTEL471_EMAIL and INTEL471_API_KEY."),
        )
    root = _data_root()
    cache = _cache_for(root, kind)
    cache_key = cache.key("GET", url, params, b"", _scope())
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    if offline:
        cached = cache.get(cache_key)
        if cached is not None:
            payload = _load(cached.body.decode("utf-8"))
            state = "hit" if cache.fresh(cached) else "stale"
            return payload, state, ""
        return (
            None,
            "snapshot",
            ("Intel 471 is unavailable offline and no cached or snapshot response is available."),
        )
    client = _client(root, cache)
    try:
        _acquire(root)
        response = client.get(
            url,
            params=params,
            headers=_auth_headers(),
            ttl=900,
            skip_cache=force_live,
        )
    except EgressDenied as exc:
        # A refused host is a policy stop. A cached copy must not hide it.
        return None, "snapshot", _scrub(str(exc))
    except (HttpError, TimeoutError, RateLimited) as exc:
        cached = None if force_live else cache.get(cache_key)
        if cached is not None:
            payload = _load(cached.body.decode("utf-8"))
            return payload, "stale", ""
        return None, "snapshot", _scrub(str(exc)) or "Intel 471 is unavailable"
    finally:
        client.close()
    if response.status in (401, 403):
        return (
            None,
            "snapshot",
            (
                f"Intel 471 refused the request (HTTP {response.status}). "
                "Check INTEL471_EMAIL and INTEL471_API_KEY."
            ),
        )
    if response.status == 429:
        return (
            None,
            "snapshot",
            ("Intel 471 rate limited the request (429). Retry-After was honoured."),
        )
    if response.status >= 400:
        return None, "snapshot", f"Intel 471 returned HTTP {response.status}"
    payload = _load(response.body.decode("utf-8"))
    if payload is None:
        return None, response.cache, "Intel 471 payload was not usable"
    return payload, response.cache, ""


def _guard_request(url: str, params: dict | None) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or host != "api.intel471.com":
        return "Intel 471 requests stay on https://api.intel471.com"
    path = parts.path.rstrip("/") or "/"
    if path not in _READ_PATHS and not path.startswith("/v1/watcherGroups"):
        return "Intel 471 connector only reads alerts, credentials and watcher configuration"
    if params and "markAsRead" in params and str(params["markAsRead"]).lower() != "false":
        return "Intel 471 connector does not mark alerts as read"
    if params and any(name.lower() == "passwordplain" for name in params):
        return "Intel 471 connector does not send passwords"
    return ""


def _client(root: Path, cache):
    kwargs = {}
    if _TRANSPORT is not None:
        kwargs["transport"] = _TRANSPORT
    if _SLEEPER is not None:
        kwargs["sleeper"] = _SLEEPER
    if _RNG is not None:
        kwargs["rng"] = _RNG
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    return HttpClient(
        "intel471",
        policy=EgressPolicy(allowlist, "intel471"),
        cache=cache,
        limiter=RateLimiter(root / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=_RATE,
        burst=_BURST,
        window="rolling",
        auth_scope=_scope(),
        timeout=30,
        **kwargs,
    )


def _acquire(root: Path) -> None:
    RateLimiter(root / "rate_limit.sqlite").acquire(
        "intel471:api.intel471.com",
        rate=_RATE,
        burst=_BURST,
        window="rolling",
    )


def _auth_headers() -> dict[str, str]:
    email = lookup("INTEL471_EMAIL") or ""
    key = lookup("INTEL471_API_KEY") or ""
    token = base64.b64encode(f"{email}:{key}".encode()).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _configured() -> bool:
    return lookup("INTEL471_EMAIL") is not None and lookup("INTEL471_API_KEY") is not None


def _scrub(message: str) -> str:
    email = lookup("INTEL471_EMAIL") or ""
    key = lookup("INTEL471_API_KEY") or ""
    if email and key:
        token = base64.b64encode(f"{email}:{key}".encode()).decode("ascii")
        message = message.replace(token, "[REDACTED]")
    if email:
        message = message.replace(email, "[REDACTED]")
    if key:
        message = message.replace(key, "[REDACTED]")
    return redact(message)


def _cache_for(root: Path, kind: str):
    if kind == "credentials":
        # Occurrence rows can carry logins and passwords. Only counts leave this module,
        # so the raw body is never kept.
        return HttpCache(root / "http_cache.sqlite", persistence="none")
    return _session_cache(root)


def _session_cache(root: Path):
    global _CACHE, _CACHE_PATH
    path = root / "http_cache.sqlite"
    if _CACHE is None or _CACHE_PATH != path:
        # Session only. The Titan client's 10 hour GiR cache is not used.
        _CACHE = cache_for_terms(path, _terms())
        _CACHE_PATH = path
    return _CACHE


def _terms():
    return get_vendor("intel471").terms


def _max_pages() -> int:
    return get_vendor("intel471").max_pages


def _snapshot_active() -> bool:
    return bool(os.environ.get("CYBERAU_INTEL471_SNAPSHOT"))


def _snapshot_body(kind: str) -> str | None:
    raw = os.environ.get("CYBERAU_INTEL471_SNAPSHOT")
    if not raw:
        return None
    path = Path(raw)
    if path.is_dir():
        file = path / _SNAPSHOTS[kind]
        if not file.is_file():
            return None
        return file.read_text(encoding="utf-8")
    if path.is_file():
        return path.read_text(encoding="utf-8")
    return None


def _schema_text() -> str:
    raw = os.environ.get("CYBERAU_INTEL471_SNAPSHOT")
    if raw:
        path = Path(raw)
        if path.is_dir():
            path = path / _SNAPSHOTS["alerts"]
        if path.is_file():
            return path.read_text(encoding="utf-8")
    return (_PACKAGE / "data" / "alerts.json").read_text(encoding="utf-8")


def _load(text: str) -> dict | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _drift_rows(
    payload: dict,
    key: str,
    required: tuple[str, ...],
    any_of: tuple[tuple[str, ...], ...] = (),
) -> str | None:
    if key not in payload:
        return f"Intel 471 schema drift, missing {key}"
    rows = payload[key]
    if not isinstance(rows, list):
        return f"Intel 471 {key} payload was not usable"
    if not rows:
        return None
    first = rows[0]
    if not isinstance(first, dict):
        return f"Intel 471 {key} payload was not usable"
    missing = [name for name in required if name not in first]
    for options in any_of:
        if not any(name in first for name in options):
            missing.append(options[0])
    if missing:
        return "Intel 471 schema drift, missing " + ", ".join(missing)
    return None


def _check_records(name: str, records: list[dict]) -> str:
    if not records:
        return ""
    schema = json.loads((_PACKAGE / "schema" / f"{name}.response.json").read_text())
    validator = Draft202012Validator(schema)
    for record in records:
        if next(validator.iter_errors(record), None) is not None:
            return f"Intel 471 record did not match the {name} response schema"
    return ""


def _load_watchlist() -> tuple[Watchlist | None, str]:
    raw = os.environ.get("CYBERAU_WATCHLIST")
    if raw:
        path = Path(raw)
    else:
        base = os.environ.get("CYBERAU_DATA_DIR")
        if not base:
            return None, ""
        path = Path(base) / "watchlists" / "org-exposure.yaml"
    if not path.is_file():
        return None, ""
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return None, "org-exposure watchlist could not be read"
    if not isinstance(payload, dict):
        return None, "org-exposure watchlist could not be read"
    try:
        return Watchlist.model_validate(payload), ""
    except ValidationError:
        return None, "org-exposure watchlist could not be read"


def _search_texts(watchlist: Watchlist, query: str | None) -> list[str]:
    if query:
        return [query]
    values = _domain_values(watchlist)
    values.extend(watchlist.brands)
    if watchlist.organisation:
        values.append(watchlist.organisation)
    seen: set[str] = set()
    ordered = []
    for value in values:
        folded = value.casefold()
        if folded in seen:
            continue
        seen.add(folded)
        ordered.append(value)
    return ordered


def _domain_values(watchlist: Watchlist) -> list[str]:
    values = list(watchlist.domains)
    values.extend(watchlist.email_domains)
    for item in watchlist.subsidiaries:
        for domain in item.get("domains") or []:
            if isinstance(domain, str):
                values.append(domain)
    return values


def _first_domain(watchlist: Watchlist | None) -> str | None:
    if watchlist is None:
        return None
    values = _domain_values(watchlist)
    return values[0] if values else None


def _allowed_query(query: str, watchlist: Watchlist) -> str | None:
    folded = query.strip().casefold()
    matched = _exact(folded, watchlist)
    if matched:
        return matched
    organisation = (watchlist.organisation or "").strip()
    if organisation and organisation.casefold() == folded:
        return organisation
    return None


def _allowed_domain(domain: str, watchlist: Watchlist) -> str | None:
    folded = domain.strip().casefold().rstrip(".")
    for value in _domain_values(watchlist):
        if value.casefold().rstrip(".") == folded:
            return value
    return None


def _match_any(candidates: list[str], watchlist: Watchlist) -> str | None:
    domains: list[str] = []
    others: list[str] = []
    for candidate in candidates:
        folded = candidate.casefold().strip()
        domain = _exact_kind(folded, watchlist, _domain_values(watchlist))
        if domain:
            domains.append(domain)
            continue
        host = _host_in_text(folded, watchlist)
        if host:
            domains.append(host)
            continue
        other = _exact(folded, watchlist)
        domain_values = {item.casefold() for item in _domain_values(watchlist)}
        if other and other.casefold() not in domain_values:
            others.append(other)
    if domains:
        return domains[0]
    if others:
        return others[0]
    return None


def _exact(folded: str, watchlist: Watchlist) -> str | None:
    pools = [
        *_domain_values(watchlist),
        *watchlist.brands,
        *watchlist.abns,
    ]
    for item in watchlist.subsidiaries:
        name = item.get("name")
        if isinstance(name, str):
            pools.append(name)
    return _exact_kind(folded, watchlist, pools)


def _exact_kind(folded: str, watchlist: Watchlist, values: list[str]) -> str | None:
    del watchlist
    for value in values:
        if value.casefold() == folded:
            return value
    return None


def _host_in_text(text: str, watchlist: Watchlist) -> str | None:
    for host in _domain_values(watchlist):
        needle = host.casefold()
        if len(needle) < 4:
            continue
        start = 0
        while True:
            index = text.find(needle, start)
            if index < 0:
                break
            before = text[index - 1] if index else " "
            after_at = index + len(needle)
            after = text[after_at] if after_at < len(text) else " "
            if before not in "abcdefghijklmnopqrstuvwxyz0123456789-" and after not in (
                "abcdefghijklmnopqrstuvwxyz0123456789-"
            ):
                return host
            start = index + 1
    return None


def _subject(value: str, watchlist: Watchlist) -> Subject:
    folded = value.casefold()
    kind = "domain"
    if any(item.casefold() == folded for item in watchlist.domains):
        kind = "domain"
    elif any(item.casefold() == folded for item in watchlist.brands):
        kind = "brand"
    elif any(item.casefold() == folded for item in watchlist.email_domains):
        kind = "email_domain"
    elif any(item.casefold() == folded for item in watchlist.abns):
        kind = "abn"
    else:
        for item in watchlist.subsidiaries:
            name = item.get("name")
            if isinstance(name, str) and name.casefold() == folded:
                kind = "brand"
                break
    return Subject(type=kind, value=value, watchlist_entry=value)


def _group_index(payload: dict) -> dict[str, dict]:
    found = {}
    groups = payload.get("watcherGroups") or payload.get("watcher_groups") or []
    for group in groups:
        if isinstance(group, dict) and group.get("uid"):
            found[str(group["uid"])] = group
    return found


def _watcher_name(item: dict, groups: dict[str, dict]) -> str:
    uid = str(item.get("watcherGroupUid") or item.get("watcher_group_uid") or "")
    group = groups.get(uid) or {}
    name = group.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    watcher_uid = str(item.get("watcherUid") or item.get("watcher_uid") or "")
    for watcher in group.get("watchers") or []:
        if not isinstance(watcher, dict):
            continue
        if watcher_uid and str(watcher.get("uid") or "") != watcher_uid:
            continue
        description = watcher.get("description")
        if isinstance(description, str) and description.strip():
            return description.strip()
    return uid or "watcher"


def _alert_candidates(item: dict, groups: dict[str, dict]) -> list[str]:
    values = [_watcher_name(item, groups)]
    uid = str(item.get("watcherGroupUid") or item.get("watcher_group_uid") or "")
    group = groups.get(uid) or {}
    for watcher in group.get("watchers") or []:
        if isinstance(watcher, dict) and isinstance(watcher.get("description"), str):
            values.append(watcher["description"])
    return values


def _group_selected(item: dict, name: str, watcher_group: str) -> bool:
    token = watcher_group.casefold()
    uid = str(item.get("watcherGroupUid") or item.get("watcher_group_uid") or "")
    return token in {uid.casefold(), name.casefold()}


def _source_type(item: dict) -> str:
    for key, name in _SOURCE_FIELDS:
        value = item.get(key)
        if isinstance(value, dict) and value:
            return name
    return "alert"


def _breach_candidates(item: dict) -> list[str]:
    values = []
    title = _breach_title(item)
    if title:
        values.append(title)
    victim = _victim_name(item)
    if victim:
        values.append(victim)
    for url in _victim_urls(item):
        values.append(url)
    return values


def _breach_body(item: dict) -> dict:
    data = item.get("data")
    if not isinstance(data, dict):
        return {}
    body = data.get("breach_alert") or data.get("breachAlert") or {}
    return body if isinstance(body, dict) else {}


def _breach_title(item: dict) -> str:
    title = _breach_body(item).get("title")
    if isinstance(title, str) and title.strip():
        return title.strip()
    return "Breach alert"


def _victim_name(item: dict) -> str:
    victim = _breach_body(item).get("victim")
    if not isinstance(victim, dict):
        return ""
    name = victim.get("name")
    return name.strip() if isinstance(name, str) else ""


def _victim_urls(item: dict) -> list[str]:
    victim = _breach_body(item).get("victim")
    if not isinstance(victim, dict):
        return []
    urls = victim.get("urls") or []
    return [url for url in urls if isinstance(url, str)]


def _credential_body(row: dict) -> dict:
    data = row.get("data")
    if not isinstance(data, dict):
        return {}
    body = data.get("credential") or {}
    return body if isinstance(body, dict) else {}


def _malware(row: dict) -> bool:
    data = row.get("data")
    if not isinstance(data, dict):
        return False
    return bool(data.get("detected_malware") or data.get("detectedMalware"))


def _moment(item: dict) -> datetime | None:
    if not isinstance(item, dict):
        return None
    for key in ("foundTime", "found_time", "last_updated", "lastUpdated", "released_at"):
        parsed = _epoch(item.get(key))
        if parsed is not None:
            return parsed
    activity = item.get("activity")
    if isinstance(activity, dict):
        for key in ("last", "first"):
            parsed = _epoch(activity.get(key))
            if parsed is not None:
                return parsed
    return _moment(_breach_body(item)) if _breach_body(item) else None


def _epoch(value) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    if isinstance(value, str) and not value.isdigit():
        return None
    number = int(value)
    if number > 10_000_000_000:
        number = int(number / 1000)
    try:
        return datetime.fromtimestamp(number, UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _on_or_after(moment: datetime, since: str | None) -> bool:
    if not since:
        return True
    local = moment.astimezone(_SYDNEY).date().isoformat()
    return local >= since


def _from_value(since: str | None) -> str | None:
    if not since:
        return None
    day = datetime.strptime(since, "%Y-%m-%d").replace(tzinfo=_SYDNEY)
    return str(int(day.timestamp() * 1000))


def _iso(moment: datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _check_since(since: str | None) -> str:
    if since is None or since == "":
        return ""
    message = "since must be YYYY-MM-DD in Australia/Sydney"
    if not isinstance(since, str) or not _DATE.fullmatch(since):
        return message
    try:
        datetime.strptime(since, "%Y-%m-%d")
    except ValueError:
        return message
    return ""


def _check_limit(limit: int) -> str:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
        return "limit must be between 1 and 1000"
    return ""


def _check_query(query: str) -> str:
    if not isinstance(query, str) or len(query.strip()) < 2:
        return "query must be at least 2 characters"
    return ""


def _check_domain(domain: str) -> str:
    if not isinstance(domain, str) or not domain.strip():
        return "domain is required"
    if "://" in domain or "/" in domain or len(domain) > 253:
        return "domain must be a hostname"
    return ""


def _uid(item: dict) -> str:
    raw = item.get("uid")
    if isinstance(raw, bool) or not isinstance(raw, (str, int)):
        return ""
    text = str(raw)
    # The uid is feed text that is returned unwrapped and kept as source_ref.
    return text if _UID.fullmatch(text) else ""


def _origin_notes(cache: str) -> tuple[str, ...]:
    if cache == "snapshot" and _snapshot_active():
        return (
            "Served from a local snapshot (CYBERAU_INTEL471_SNAPSHOT), not a live "
            "Intel 471 result. Nothing was stored.",
        )
    if cache == "stale":
        return ("Served from a cached copy that has expired. Intel 471 was not reached.",)
    return ()


def _envelope(data, cache: str, urls: tuple[str, ...], warnings: tuple[str, ...] = ()) -> dict:
    cleaned = tuple(_scrub(item) for item in warnings)
    return envelope(
        "intel471",
        data,
        urls=list(urls),
        cache=cache,
        warnings=cleaned,
        attribution=_terms().attribution,
    )


def _data_root() -> Path:
    raw = os.environ.get("CYBERAU_DATA_DIR")
    if raw:
        path = Path(raw)
        path.mkdir(parents=True, exist_ok=True)
        return path
    return data_dir()


def _scope() -> str:
    email = lookup("INTEL471_EMAIL") or ""
    if not email:
        return "anonymous"
    return hashlib.sha256(email.encode()).hexdigest()[:16]


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


def connector() -> Intel471Connector:
    return Intel471Connector()


register_connector("intel471", connector)
