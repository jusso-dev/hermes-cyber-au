"""Read-only CrowdStrike Falcon Adversary Intelligence Recon connector.

Recon HTTP calls are made by the official FalconPy SDK. This module supplies
the session that enforces egress, the local rate limit and Retry-After.
Creating or changing rules is out of scope.
"""

import json
import os
import re
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated
from zoneinfo import ZoneInfo

import httpx
import requests
import yaml
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.ratelimit import RateLimiter
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
from cyberau_premium.redact import redact_text
from cyberau_premium.store import ExposureStore
from falconpy import Recon
from pydantic import Field

DEFAULT_BASE = "https://api.crowdstrike.com"
# Falcon's own ceiling is returned in headers and is much higher. Stay under it.
_RATE = 10.0
_BURST = 20
_REDIRECTS = {301, 302, 303, 307, 308}
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_DATA = Path(__file__).resolve().parent / "data"
_Date = Annotated[str, Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")]
_Limit = Annotated[int, Field(ge=1, le=500)]

_TRANSPORT = None
_SLEEPER = None
_RESOLVER = None
_CACHE: HttpCache | None = None


def cs_recon_notifications(since: _Date | None = None, limit: _Limit = 100) -> dict:
    """Notifications since a Sydney date, with rule name, topic and match summary."""
    problem = _validate(since, limit)
    if problem:
        return _envelope([], "snapshot", (problem,), "notifications")
    present, raw, state, warning = _records("notifications", _blank(since), int(limit))
    if warning:
        return _envelope([], state, (warning,), "notifications")
    if state != "snapshot":
        _persist(raw, _load_watchlist())
    return _envelope(present, state, _notice(state), "notifications")


def cs_recon_rules() -> dict:
    """Monitoring rules and their topics. Read only."""
    present, _raw, state, warning = _records("rules", None, 500)
    if warning:
        return _envelope([], state, (warning,), "rules")
    return _envelope(present, state, _notice(state), "rules")


def connector() -> PremiumConnector:
    return CrowdStrikeRecon()


class CrowdStrikeRecon(PremiumConnector):
    def __init__(self) -> None:
        spec = get_vendor("csrecon")
        super().__init__(
            key="crowdstrike-recon",
            server_name="csrecon",
            attribution=spec.terms.attribution,
            tools=[
                ToolSpec(
                    "cs_recon_notifications",
                    "Recon notifications since a date, with rule name, topic and match summary.",
                    cs_recon_notifications,
                ),
                ToolSpec(
                    "cs_recon_rules",
                    "Monitoring rules and their topics. Read only.",
                    cs_recon_rules,
                ),
            ],
            vendor=spec.server,
            licence_env=tuple(spec.licence_env),
            terms=spec.terms,
            quota=spec.quota,
        )

    def exposure_for(self, watchlist: Watchlist, since: date) -> list[ExposureFinding]:
        _present, raw, state, warning = _records("notifications", since.isoformat(), 500)
        if warning or not raw or state == "snapshot":
            # A bundled snapshot is synthetic. It must never become a stored finding.
            return []
        return _persist(raw, watchlist)

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema:
            problem = schema_drift(_bundled("notifications") or {})
            if problem:
                return Probe(self.key, False, problem)
            if not live:
                return Probe(self.key, True, "schema ok")
        missing = _missing_licence()
        if missing:
            if live:
                return Probe(self.key, False, f"not configured: {missing}")
            return Probe(self.key, True, "not configured")
        if not live:
            return Probe(self.key, True, "offline ok")
        if _offline():
            return Probe(self.key, False, "CYBERAU_OFFLINE is set, live check not run")
        warning = _live_probe()
        if warning:
            return Probe(self.key, False, warning)
        return Probe(self.key, True, "live ok")


def schema_drift(payload: dict) -> str | None:
    """Fail when a notification entity no longer has the fields we store."""
    if not isinstance(payload, dict):
        return "CrowdStrike payload was not usable"
    resources = payload.get("resources")
    if not isinstance(resources, list):
        return "CrowdStrike payload has no resources list"
    if not resources:
        return None
    item = resources[0]
    if not isinstance(item, dict):
        return "CrowdStrike schema drift, notification is not an object"
    for name in ("id", "rule_name", "rule_topic"):
        if name not in item:
            return f"CrowdStrike schema drift, missing {name}"
    return None


def render_connector_doc() -> str:
    """Connector page. Quotes the catalogue terms. Not legal advice."""
    spec = get_vendor("csrecon")
    terms = spec.terms
    required = "\n".join(f"- `{name}` (required)" for name in spec.licence_env)
    optional = "\n".join(f"- `{name}` (optional)" for name in spec.optional_env)
    lines = [
        "# CrowdStrike Falcon Adversary Intelligence Recon",
        "",
        "Read-only notifications and monitoring rules from Falcon Adversary",
        "Intelligence Recon. Creating or changing rules is out of scope. Rules are",
        "managed in Falcon. Calls go through the official FalconPy SDK",
        "(`query_notifications`, `get_notifications`, `query_rules`, `get_rules`).",
        "",
        "Off by default: licence terms. A fresh install renders `enabled: false`",
        "for `csrecon` even when the licence variables are set. Set `enabled: true`",
        "in the profile `config.yaml` to turn it on. `hermes profile update` keeps",
        "that choice.",
        "",
        "Premium doctor reports `csrecon: off (paid, bring your own licence)` until",
        "then. This page is the terms link. A skill that calls this connector states",
        "these terms before the first call in a session.",
        "",
        "## Tools",
        "",
        "| Tool | What it returns |",
        "| --- | --- |",
        "| `cs_recon_notifications` | Notifications since a date: rule name, topic, summary |",
        "| `cs_recon_rules` | Monitoring rules and their topics |",
        "",
        "Rule names, filters and match summaries are untrusted text.",
        "",
        "## Terms",
        "",
        "| Flag | Default |",
        "| --- | --- |",
        f"| `cache` | `{terms.cache}` |",
        f"| `cache_ttl_max_s` | `{terms.cache_ttl_max_s}` |",
        f"| `store` | `{terms.store}` |",
        f"| `stix_export` | `{str(terms.stix_export).lower()}` |",
        f"| `share_outside_profile` | `{str(terms.share_outside_profile).lower()}` |",
        f"| `redistribution` | `{terms.redistribution}` |",
        "",
        terms.attribution,
        "",
        "## Licence environment",
        "",
        "Names only. Put values in the profile `.env`. Do not commit them.",
        "",
        required,
        optional,
        "",
        "`FALCON_BASE_URL` defaults to `https://api.crowdstrike.com`. The API client",
        "needs the Recon monitoring rules read scope only.",
        "",
        "CrowdStrike Falcon is a commercial product. This connector is not endorsed",
        "by CrowdStrike.",
        "",
    ]
    return "\n".join(lines)


class GovernedSession(requests.Session):
    """Transport for FalconPy. Refuses writes, other hosts and unlisted redirects."""

    def __init__(self, *, policy: EgressPolicy, limiter: RateLimiter, transport, sleeper):
        super().__init__()
        self.policy = policy
        self.limiter = limiter
        self._sleeper = sleeper
        self.refusal: str | None = None
        self._http = httpx.Client(transport=transport, follow_redirects=False, timeout=30)

    def close(self) -> None:
        self._http.close()
        super().close()

    def request(self, method, url, **kwargs):  # noqa: ANN001
        verb = str(method).upper()
        path = httpx.URL(str(url)).path.rstrip("/") or "/"
        if kwargs.get("files") or verb not in {"GET", "POST"}:
            raise PermissionError("CrowdStrike Recon connector is read-only")
        if verb == "POST" and path != "/oauth2/token":
            raise PermissionError("CrowdStrike Recon connector is read-only")
        current = str(url)
        current_method = verb
        body_json = kwargs.get("json")
        body_data = kwargs.get("data")
        headers = dict(kwargs.get("headers") or {})
        params = kwargs.get("params")
        allow_redirects = bool(kwargs.get("allow_redirects"))
        timeout = _timeout(kwargs.get("timeout"))
        redirects = 0
        attempt = 0
        while redirects < 5:
            self.policy.check(current)
            host = httpx.URL(current).host or ""
            self.limiter.acquire(
                f"crowdstrike-recon:{host}",
                rate=_RATE,
                burst=_BURST,
                window="rolling",
            )
            request = {"headers": headers, "params": params, "timeout": timeout}
            if body_json is not None:
                request["json"] = body_json
            elif body_data is not None:
                request["data"] = body_data
            try:
                response = self._http.request(current_method, current, **request)
            except httpx.TimeoutException as exc:
                raise TimeoutError("CrowdStrike request timed out") from exc
            if response.status_code in _REDIRECTS:
                location = response.headers.get("location")
                if not location:
                    return _as_requests(response, current)
                target = str(httpx.URL(current).join(location))
                try:
                    self.policy.check(target)
                except EgressDenied as exc:
                    # FalconPy swallows transport errors from the token call and
                    # continues. Remember the refusal so the tool can still stop.
                    self.refusal = str(exc)
                    raise
                if not allow_redirects:
                    return _as_requests(response, current)
                redirects += 1
                current = target
                if response.status_code in {301, 302, 303}:
                    current_method = "GET"
                    body_json = None
                    body_data = None
                    params = None
                continue
            if response.status_code == 429 and attempt < 3:
                self._sleeper(_retry_delay(response.headers))
                attempt += 1
                continue
            if response.status_code in {401, 403}:
                # Token failures are easy for FalconPy to swallow before the
                # Recon call. Keep the licence message for the tool result.
                self.refusal = _auth_message(response.status_code)
            return _as_requests(response, current)
        raise EgressDenied("too many redirects")


def _records(
    kind: str,
    since: str | None,
    limit: int,
) -> tuple[list[dict], list[dict], str, str]:
    missing = _missing_licence()
    if missing:
        return [], [], "snapshot", missing
    item, cached = _recall(kind, since, limit)
    cache = _http_cache()
    if _offline():
        if cached is not None:
            return _present(kind, cached), cached, "stale", ""
        return _from_snapshot(kind, since, limit)
    if item is not None and cached is not None and cache.fresh(item):
        return _present(kind, cached), cached, "hit", ""
    try:
        raw, warning = _collect(kind, since, limit)
    except TimeoutError:
        if cached is not None:
            return _present(kind, cached), cached, "stale", ""
        return (
            [],
            [],
            "snapshot",
            ("CrowdStrike request timed out and no cached result is available"),
        )
    if warning or raw is None:
        return [], [], "snapshot", warning or "CrowdStrike payload was not usable"
    if kind == "notifications":
        raw = [_scrub_notification(row) for row in _select(raw, since, limit)]
    else:
        raw = [_scrub_rule(row) for row in raw[:limit]]
    _remember(kind, since, limit, raw)
    return _present(kind, raw), raw, "miss", ""


def _collect(kind: str, since: str | None, limit: int) -> tuple[list[dict] | None, str]:
    holder: dict[str, list[dict]] = {}

    def run(client: Recon) -> str:
        rows, warning = _pages(client, kind, since, limit)
        if warning:
            return warning
        holder["rows"] = rows or []
        return ""

    warning = _open(run)
    if warning:
        return None, warning
    return holder.get("rows", []), ""


def _live_probe() -> str:
    def run(client: Recon) -> str:
        _result, warning = _interpret(client.query_rules(limit=1))
        return warning

    try:
        return _open(run)
    except TimeoutError:
        return "CrowdStrike request timed out"


def _open(fn) -> str:
    base = _base_url()
    policy = _policy()
    try:
        policy.check(base + "/oauth2/token")
    except EgressDenied as exc:
        return _safe(str(exc))
    session = GovernedSession(
        policy=policy,
        limiter=_limiter(),
        transport=_TRANSPORT,
        sleeper=_SLEEPER or __import__("time").sleep,
    )
    try:
        client = Recon(
            client_id=lookup("FALCON_CLIENT_ID"),
            client_secret=lookup("FALCON_CLIENT_SECRET"),
            base_url=base,
            timeout=30,
            session=session,
            user_agent=USER_AGENT,
            pythonic=False,
        )
        try:
            result = fn(client)
        except TimeoutError:
            if session.refusal:
                return session.refusal
            raise
        if session.refusal:
            return session.refusal
        return result
    except TimeoutError:
        raise
    except Exception as exc:
        return _safe(str(exc))
    finally:
        session.close()


def _pages(client: Recon, kind: str, since: str | None, limit: int):
    if kind == "notifications":
        query = client.query_notifications
        fetch = client.get_notifications
        fql = _fql(since)
    else:
        query = client.query_rules
        fetch = client.get_rules
        fql = None
    ids: list[str] = []
    offset = 0
    pages = 0
    max_pages = get_vendor("csrecon").max_pages
    while len(ids) < limit and pages < max_pages:
        page = min(500, limit - len(ids))
        kwargs: dict = {"limit": page, "offset": offset}
        if kind == "notifications":
            kwargs["sort"] = "created_date|desc"
        if fql:
            kwargs["filter"] = fql
        result, warning = _interpret(query(**kwargs))
        if warning:
            return None, warning
        batch = _ids(_resources(result))
        if batch is None:
            return None, "CrowdStrike payload was not usable"
        if not batch:
            break
        for item in batch:
            if item not in ids:
                ids.append(item)
        offset += len(batch)
        pages += 1
        if len(batch) < page:
            break
    chosen = ids[:limit]
    if not chosen:
        return [], ""
    rows: list[dict] = []
    for start in range(0, len(chosen), 100):
        result, warning = _interpret(fetch(ids=chosen[start : start + 100]))
        if warning:
            return None, warning
        entities = _entities(_resources(result))
        if entities is None:
            return None, "CrowdStrike payload was not usable"
        rows.extend(entities)
    return rows, ""


def _interpret(result) -> tuple[dict | None, str]:
    if not isinstance(result, dict):
        return None, "CrowdStrike payload was not usable"
    message = _error_message(result)
    if _is_timeout(message):
        raise TimeoutError("CrowdStrike request timed out")
    if "not allowlisted" in message or "read-only" in message:
        return None, _safe(message)
    status = result.get("status_code")
    code = int(status) if isinstance(status, int) else 0
    if code in {401, 403}:
        return None, _auth_message(code)
    if code == 429:
        return None, (
            "CrowdStrike returned 429. The connector honoured Retry-After and the limit still held."
        )
    if code >= 400:
        return None, _safe(message) or f"CrowdStrike status {code}"
    if _resources(result) is None:
        return None, "CrowdStrike payload was not usable"
    return result, ""


def _resources(result: dict | None) -> list | None:
    if not isinstance(result, dict):
        return None
    body = result.get("body")
    if not isinstance(body, dict):
        return None
    resources = body.get("resources")
    if not isinstance(resources, list):
        return None
    return resources


def _ids(resources: list | None) -> list[str] | None:
    if resources is None:
        return None
    ids: list[str] = []
    for item in resources:
        if isinstance(item, str) and item:
            ids.append(item)
        elif isinstance(item, dict) and item.get("id"):
            ids.append(str(item["id"]))
        else:
            return None
    return ids


def _entities(resources: list | None) -> list[dict] | None:
    if resources is None:
        return None
    if any(not isinstance(item, dict) or not item.get("id") for item in resources):
        return None
    return [item for item in resources if isinstance(item, dict)]


def _from_snapshot(
    kind: str,
    since: str | None,
    limit: int,
) -> tuple[list[dict], list[dict], str, str]:
    payload = _bundled(kind)
    resources = None if payload is None else payload.get("resources")
    if not isinstance(resources, list):
        return [], [], "snapshot", "unavailable: no CrowdStrike snapshot or cache"
    rows = [row for row in resources if isinstance(row, dict) and row.get("id")]
    if kind == "notifications":
        rows = [_scrub_notification(row) for row in _select(rows, since, limit)]
    else:
        rows = [_scrub_rule(row) for row in rows[:limit]]
    return _present(kind, rows), rows, "snapshot", ""


def _present(kind: str, rows: list) -> list[dict]:
    if kind == "notifications":
        return [_notification(row) for row in rows if isinstance(row, dict)]
    return [_rule(row) for row in rows if isinstance(row, dict)]


def _notification(item: dict) -> dict:
    observed = str(item.get("created_date") or item.get("item_date") or "")
    return {
        "id": str(item.get("id") or ""),
        "rule_name": untrusted_text(str(item.get("rule_name") or ""), "csrecon"),
        "topic": str(item.get("rule_topic") or ""),
        "match_summary": untrusted_text(_summary(item), "csrecon"),
        "observed_at": observed,
        "status": str(item.get("status") or ""),
    }


def _rule(item: dict) -> dict:
    return {
        "id": str(item.get("id") or ""),
        "name": untrusted_text(str(item.get("name") or ""), "csrecon"),
        "topic": str(item.get("topic") or ""),
        "priority": str(item.get("priority") or ""),
        "filter": untrusted_text(str(item.get("filter") or ""), "csrecon"),
    }


def _summary(item: dict) -> str:
    summary = item.get("summary")
    if isinstance(summary, str) and summary.strip():
        return summary
    typos = item.get("typosquatting")
    if isinstance(typos, dict):
        parent = typos.get("parent_domain")
        parent_domain = ""
        if isinstance(parent, dict) and parent.get("base_domain"):
            parent_domain = str(parent["base_domain"])
        base = str(typos.get("base_domain") or "")
        parts = [part for part in (base, parent_domain) if part]
        if parts:
            return "Typosquat match for " + ", ".join(parts)
    return str(item.get("rule_name") or "")


def _scrub_notification(item: dict) -> dict:
    kept = dict(item)
    for field in ("summary", "rule_name"):
        if isinstance(kept.get(field), str):
            kept[field] = redact_text(kept[field])
    return kept


def _scrub_rule(item: dict) -> dict:
    kept = dict(item)
    for field in ("name", "filter"):
        if isinstance(kept.get(field), str):
            kept[field] = redact_text(kept[field])
    return kept


def _select(rows: list[dict], since: str | None, limit: int) -> list[dict]:
    chosen = rows
    if since:
        start = _since_utc(since)
        chosen = [row for row in rows if _on_or_after(row, start)]
    chosen = sorted(chosen, key=_sort_key, reverse=True)
    return chosen[:limit]


def _persist(rows: list[dict], watchlist: Watchlist | None) -> list[ExposureFinding]:
    if watchlist is None or not rows:
        return []
    spec = get_vendor("csrecon")
    store = ExposureStore(data_dir() / "intel.sqlite")
    kept: list[ExposureFinding] = []
    for item in rows:
        finding = _finding(item, watchlist, spec.server, spec.terms.stix_export)
        if finding is None:
            continue
        status = store.write(finding, terms=spec.terms, watchlist=watchlist)
        if status in {"stored", "updated"}:
            kept.append(finding)
    return kept


def _finding(item: dict, watchlist: Watchlist, vendor: str, stix_export: bool):
    subject = _match_subject(item, watchlist)
    if subject is None:
        return None
    observed = _parse_dt(str(item.get("created_date") or "")) or datetime.now(UTC)
    source_ref = str(item.get("id") or "")
    summary = str(item.get("summary") or "")
    return ExposureFinding(
        finding_id=finding_id(vendor, "dark_web_mention", subject.value, source_ref),
        vendor=vendor,
        kind="dark_web_mention",
        subject=subject,
        observed_at=observed,
        first_seen=observed,
        licence_scope="store_metadata",
        confidence="vendor_reported",
        counts={"notifications": 1},
        data_classes=["dark_web_mention"],
        source_ref=source_ref,
        stix_exportable=stix_export,
        contains_personal_information="@" in summary,
    )


def _match_subject(item: dict, watchlist: Watchlist) -> Subject | None:
    known = watchlist.known_subjects()
    for value in _domains(item):
        if value.casefold() in known:
            return Subject(type="domain", value=value, watchlist_entry=value)
    rule_name = str(item.get("rule_name") or "")
    if rule_name and rule_name.casefold() in known:
        return Subject(type="brand", value=rule_name, watchlist_entry=rule_name)
    return None


def _domains(item: dict) -> list[str]:
    typos = item.get("typosquatting")
    if not isinstance(typos, dict):
        return []
    found: list[str] = []
    parent = typos.get("parent_domain")
    if isinstance(parent, dict) and isinstance(parent.get("base_domain"), str):
        found.append(parent["base_domain"])
    if isinstance(typos.get("base_domain"), str):
        found.append(typos["base_domain"])
    return found


def _load_watchlist() -> Watchlist | None:
    raw = os.environ.get("CYBERAU_WATCHLIST")
    path = Path(raw) if raw else data_dir() / "watchlists" / "org-exposure.yaml"
    if not path.is_file():
        return None
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        return None
    return Watchlist.model_validate(payload)


def _remember(kind: str, since: str | None, limit: int, rows: list[dict]) -> None:
    _http_cache().put(
        _cache_key(kind, since, limit),
        status=200,
        headers={"content-type": "application/json"},
        body=json.dumps(rows).encode(),
        ttl=3600,
    )


def _recall(kind: str, since: str | None, limit: int):
    cache = _http_cache()
    item = cache.get(_cache_key(kind, since, limit))
    if item is None:
        return None, None
    try:
        rows = json.loads(item.body.decode())
    except json.JSONDecodeError:
        return None, None
    if not isinstance(rows, list):
        return None, None
    return item, rows


def _http_cache() -> HttpCache:
    global _CACHE
    if _CACHE is None:
        _CACHE = cache_for_terms(
            data_dir() / "csrecon-http.sqlite",
            get_vendor("csrecon").terms,
        )
    return _CACHE


def _cache_key(kind: str, since: str | None, limit: int) -> str:
    if kind == "notifications":
        path = "/recon/queries/notifications/v1"
    else:
        path = "/recon/queries/rules/v1"
    return _http_cache().key(
        "GET",
        _base_url() + path,
        {"since": since or "", "limit": str(limit)},
        b"",
        _scope(),
    )


def _scope() -> str:
    import hashlib

    client = lookup("FALCON_CLIENT_ID") or "anonymous"
    return hashlib.sha256(client.encode()).hexdigest()[:16]


def _bundled(kind: str) -> dict | None:
    if kind == "notifications":
        override = os.environ.get("CYBERAU_CSRECON_SNAPSHOT")
        path = Path(override) if override else _DATA / "notifications_synthetic.json"
    else:
        path = _DATA / "rules_synthetic.json"
    if not path.is_file():
        return None
    return _load_json(path)


def _load_json(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _policy() -> EgressPolicy:
    raw = os.environ.get("CYBERAU_EGRESS_ALLOWLIST")
    path = Path(raw) if raw else Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"
    if _RESOLVER is None:
        return EgressPolicy(path, "crowdstrike-recon")
    return EgressPolicy(path, "crowdstrike-recon", resolver=_RESOLVER)


def _limiter() -> RateLimiter:
    return RateLimiter(data_dir() / "rate_limit.sqlite")


def _base_url() -> str:
    return (lookup("FALCON_BASE_URL") or DEFAULT_BASE).rstrip("/")


def _offline() -> bool:
    return os.environ.get("CYBERAU_OFFLINE") == "1"


def _missing_licence() -> str:
    names = ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET")
    missing = [name for name in names if lookup(name) is None]
    if not missing:
        return ""
    if len(missing) == 1:
        return f"{missing[0]} is not set"
    return "FALCON_CLIENT_ID and FALCON_CLIENT_SECRET are not set"


def _auth_message(code: int) -> str:
    return (
        f"CrowdStrike returned {code}. Check FALCON_CLIENT_ID and "
        "FALCON_CLIENT_SECRET. The API client needs the Recon monitoring rules read scope."
    )


def _validate(since: str | None, limit) -> str:
    if since not in (None, ""):
        try:
            if not _DATE.fullmatch(str(since)):
                raise ValueError(since)
            _since_utc(str(since))
        except (ValueError, OverflowError):
            return "since must be YYYY-MM-DD in Australia/Sydney"
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        return "limit must be between 1 and 500"
    return ""


def _notice(state: str) -> tuple[str, ...]:
    if state == "snapshot":
        return (
            "Bundled synthetic snapshot, not live CrowdStrike data. "
            "Nothing here is a real notification or rule.",
        )
    if state == "stale":
        return ("Cached copy from earlier this session, not a fresh CrowdStrike response.",)
    return ()


def _blank(since: str | None) -> str | None:
    if since in (None, ""):
        return None
    return str(since)


def _fql(since: str | None) -> str | None:
    if not since:
        return None
    stamp = _since_utc(since).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"created_date:>='{stamp}'"


def _since_utc(since: str) -> datetime:
    day = datetime.strptime(since, "%Y-%m-%d")
    local = day.replace(tzinfo=ZoneInfo("Australia/Sydney"))
    return local.astimezone(UTC)


def _on_or_after(row: dict, start: datetime) -> bool:
    parsed = _parse_dt(str(row.get("created_date") or ""))
    return parsed is not None and parsed >= start


def _sort_key(row: dict) -> datetime:
    return _parse_dt(str(row.get("created_date") or "")) or datetime.min.replace(tzinfo=UTC)


def _parse_dt(value: str) -> datetime | None:
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _error_message(result: dict) -> str:
    body = result.get("body")
    if not isinstance(body, dict):
        return ""
    errors = body.get("errors")
    if not isinstance(errors, list) or not errors:
        return ""
    first = errors[0]
    if isinstance(first, dict) and first.get("message"):
        return str(first["message"])
    if isinstance(first, str):
        return first
    return ""


def _is_timeout(message: str) -> bool:
    folded = message.casefold()
    return "timed out" in folded or "timeout" in folded


def _safe(message: str) -> str:
    text = redact(message)
    for name in ("FALCON_CLIENT_SECRET", "FALCON_CLIENT_ID"):
        value = lookup(name)
        if value:
            text = text.replace(value, "[REDACTED]")
    return text


def _timeout(value) -> float:
    if isinstance(value, tuple) and value:
        value = value[-1]
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        return 30.0
    if timeout <= 0:
        return 30.0
    return timeout


def _retry_delay(headers) -> float:
    raw = headers.get("retry-after")
    if raw is None:
        return 1.0
    try:
        return min(60.0, max(0.0, float(raw)))
    except (TypeError, ValueError):
        return 1.0


def _as_requests(response: httpx.Response, url: str) -> requests.Response:
    prepared = requests.Response()
    prepared.status_code = response.status_code
    prepared.headers = requests.structures.CaseInsensitiveDict(response.headers)
    prepared._content = response.content
    prepared.url = url
    prepared.encoding = "utf-8"
    return prepared


def _envelope(data, cache: str, warnings: tuple[str, ...], kind: str) -> dict:
    if kind == "notifications":
        paths = (
            "/recon/queries/notifications/v1",
            "/recon/entities/notifications/v1",
        )
    else:
        paths = ("/recon/queries/rules/v1", "/recon/entities/rules/v1")
    return envelope(
        "crowdstrike-recon",
        data,
        urls=[_base_url() + path for path in paths],
        cache=cache,
        warnings=warnings,
        attribution=get_vendor("csrecon").terms.attribution,
    )


register_connector("crowdstrike-recon", connector)
