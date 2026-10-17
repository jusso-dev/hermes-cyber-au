"""Read-only Recorded Future tools on the shared premium client."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, date, datetime
from pathlib import Path
from urllib.parse import quote
from zoneinfo import ZoneInfo

import yaml
from cyberau_common import USER_AGENT
from cyberau_common.egress import EgressPolicy
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
from cyberau_premium.guard import pre_tool_call
from cyberau_premium.store import ExposureStore

API = "https://api.recordedfuture.com"
IDENTITY_TTL = 12 * 3600
PLAYBOOK_TTL = 3600
SYDNEY = ZoneInfo("Australia/Sydney")
_RANSOM = re.compile(r"ransomware|extortion", re.IGNORECASE)
_DROP_KEYS = {
    "authorization",
    "clear_text_hint",
    "clear_text_value",
    "cleartext",
    "cleartext_hint",
    "cleartext_value",
    "cookie",
    "cookies",
    "exposed_secret",
    "hashes",
    "image",
    "images",
    "password",
    "screenshot",
    "screenshots",
    "secret",
}
_IMAGE_KEYS = {"screenshot", "screenshots", "image", "images", "url", "uri", "href"}
_SEARCH_CATEGORY = {
    "dark_web_brand": "dark_web",
    "domain_abuse": "domain_abuse",
    "identity_novel_exposures": "identity_novel_exposures",
    "code_repo_leakage": "code_repo_leakage",
    "third_party_risk": "third_party_risk",
}
_FROM_API_CATEGORY = {api: tool for tool, api in _SEARCH_CATEGORY.items()}
_FROM_API_CATEGORY["dark_web_brand"] = "dark_web_brand"
_DETAIL_CATEGORIES = (
    "dark_web_brand",
    "domain_abuse",
    "identity_novel_exposures",
)
_WRITE_MARKERS = (
    "update",
    "create",
    "takedown",
    "delete",
    "submit",
    "upload",
    "edit",
    "publish",
)
_ALERT_KINDS = {
    "infostealer_credential",
    "breach_credential",
    "leak_site_claim",
    "dark_web_mention",
    "typosquat_domain",
    "data_leak_disclosure",
}
_PACKAGE = Path(__file__).resolve().parent
_SAMPLES = _PACKAGE / "data" / "schema_samples.json"
_MCP_TOOLS = _PACKAGE.parents[1] / "tests" / "fixtures" / "mcp_tools_list.json"

_TRANSPORT = None
_SLEEPER = None
_RNG = None
_RESOLVER = None
_CONFIG = None
_LEDGER = None
_ROUTINE = False
_CACHE = None
_CACHE_PATH: Path | None = None
_RISK_SEEN_NAME = "risklist-seen.json"


class _BudgetStop(Exception):
    pass


def _vendor():
    return get_vendor("recordedfuture")


def _terms():
    return _vendor().terms


def _attribution() -> str:
    return _terms().attribution


def _data_dir() -> Path:
    path = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-recorded-future"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _allowlist() -> Path:
    override = os.environ.get("CYBERAU_EGRESS_ALLOWLIST")
    if override:
        return Path(override)
    return _PACKAGE.parents[2] / "egress-allowlist.yaml"


def _token() -> str | None:
    return lookup("RECORDED_FUTURE_API_TOKEN")


def _org_id() -> str | None:
    return lookup("RECORDED_FUTURE_ORG_ID")


def _cache():
    global _CACHE, _CACHE_PATH
    path = _data_dir() / "http_cache.sqlite"
    if _CACHE is None or _CACHE_PATH != path:
        _CACHE = cache_for_terms(path, _terms())
        _CACHE_PATH = path
    return _CACHE


def _live_allowed() -> bool:
    if os.environ.get("CYBERAU_OFFLINE") == "1":
        return False
    if _TRANSPORT is not None:
        return True
    if os.environ.get("PYTEST_CURRENT_TEST") and os.environ.get("CYBERAU_RF_LIVE") != "1":
        return False
    return True


def _safe(message: str) -> str:
    token = _token()
    if token:
        message = message.replace(token, "[REDACTED]")
    return redact(message)


def _result(data, cache: str, *, urls=(), warnings=()):
    return envelope(
        "recorded-future",
        data,
        urls=list(urls),
        cache=cache,
        attribution=_attribution(),
        warnings=tuple(_safe(item) for item in warnings),
    )


def _missing_token():
    return _result(
        [],
        "snapshot",
        warnings=("RECORDED_FUTURE_API_TOKEN is not set",),
    )


def _admit(tool: str) -> None:
    if _CONFIG is None:
        return
    decision = pre_tool_call(
        tool_name=tool,
        vendor="recordedfuture",
        routine=_ROUTINE,
        config=_CONFIG,
        ledger=_LEDGER,
    )
    if decision.get("block"):
        raise _BudgetStop(decision.get("message") or "Blocked recordedfuture")


def _client() -> HttpClient:
    token = _token() or ""
    scope = hashlib.sha256(token.encode()).hexdigest()[:16] if token else "anonymous"
    policy_kwargs = {}
    if _RESOLVER is not None:
        policy_kwargs["resolver"] = _RESOLVER
    return HttpClient(
        "recorded-future",
        policy=EgressPolicy(_allowlist(), "recorded-future", **policy_kwargs),
        cache=_cache(),
        limiter=RateLimiter(_data_dir() / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=5,
        burst=20,
        window="rolling",
        timeout=60,
        auth_scope=scope,
        offline=os.environ.get("CYBERAU_OFFLINE") == "1",
        transport=_TRANSPORT,
        sleeper=_SLEEPER,
        rng=_RNG,
    )


def _request(
    method: str,
    url: str,
    *,
    body: dict | None = None,
    params: dict | None = None,
    ttl: int,
    tool: str,
    parse_json: bool = True,
) -> tuple[dict | None, str, str, object | None]:
    """Return payload, cache state, warning, and the raw response."""
    if not _token():
        return None, "snapshot", "RECORDED_FUTURE_API_TOKEN is not set", None
    offline = os.environ.get("CYBERAU_OFFLINE") == "1"
    if not offline and not _live_allowed():
        return None, "snapshot", "unavailable", None
    try:
        _admit(tool)
    except _BudgetStop as exc:
        return None, "snapshot", str(exc), None
    headers = {"X-RFToken": _token() or ""}
    client = _client()
    try:
        if method == "POST":
            response = client.post_json(url, body or {}, headers=headers, ttl=ttl)
        elif method == "HEAD":
            response = client._fetch(
                "HEAD",
                url,
                params=params,
                headers=headers,
                content=None,
                ttl=ttl,
                stale_if_error=86400,
            )
        else:
            response = client.get(url, params=params, headers=headers, ttl=ttl)
    except (HttpError, Exception) as exc:
        message = "unavailable" if offline else (_safe(str(exc)) or "unavailable")
        return None, "snapshot", message, None
    finally:
        client.close()
    state = _cache_state(response.cache)
    if response.status in {401, 403}:
        return None, "snapshot", "RECORDED_FUTURE_API_TOKEN was rejected", response
    if response.status == 429:
        return None, state, "Recorded Future returned 429", response
    if response.status >= 400:
        return None, state, f"upstream status {response.status}", response
    if not parse_json:
        return {}, state, "", response
    if not response.body:
        return {}, state, "", response
    try:
        payload = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, state, "upstream payload was not usable", response
    if not isinstance(payload, dict):
        return None, state, "upstream payload was not usable", response
    return payload, state, "", response


def _cache_state(state: str) -> str:
    if os.environ.get("CYBERAU_OFFLINE") == "1" and state == "hit":
        return "stale"
    return state


def _since_iso(day: date) -> str:
    start = datetime(day.year, day.month, day.day, tzinfo=SYDNEY)
    return start.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_day(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _parse_dt(value) -> datetime:
    text = _time_text(value)
    if not text:
        return datetime.now(UTC)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(UTC)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _time_text(value) -> str | None:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, dict):
        for key in ("timestamp", "time", "value", "date"):
            item = value.get(key)
            if isinstance(item, str) and item:
                return item
    return None


def _label(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("status", "name", "value", "label"):
            item = value.get(key)
            if isinstance(item, str):
                return item
    return ""


def _combine(states: list[str]) -> str:
    if not states:
        return "snapshot"
    if "stale" in states:
        return "stale"
    if "miss" in states:
        return "miss"
    if "hit" in states:
        return "hit"
    return states[0]


def _watch_domains(watchlist: Watchlist) -> list[str]:
    values: list[str] = []
    for domain in [*watchlist.domains, *watchlist.email_domains]:
        if domain and domain not in values:
            values.append(domain)
    for item in watchlist.subsidiaries:
        for domain in item.get("domains") or []:
            if isinstance(domain, str) and domain not in values:
                values.append(domain)
    excluded = {item.casefold() for item in watchlist.exclude}
    return [item for item in values if item.casefold() not in excluded][:50]


def _own_needles(watchlist: Watchlist) -> list[str]:
    values = _watch_domains(watchlist)
    values.extend(watchlist.brands)
    for item in watchlist.subsidiaries:
        name = item.get("name")
        if isinstance(name, str) and name not in values:
            values.append(name)
    excluded = {item.casefold() for item in watchlist.exclude}
    return [item for item in values if item and item.casefold() not in excluded]


def _mentions(text: str, needle: str) -> bool:
    if not text or not needle:
        return False
    hay = text.casefold()
    pin = needle.casefold()
    if "." in pin:
        return pin in hay
    return re.search(rf"(?<![\w]){re.escape(pin)}(?![\w])", hay) is not None


def _matched_subject(text: str, watchlist: Watchlist) -> tuple[str, str] | None:
    for needle in _own_needles(watchlist):
        if _mentions(text, needle):
            kind = "domain" if "." in needle else "brand"
            return kind, needle
    return None


def _watchlist_path() -> Path | None:
    override = os.environ.get("CYBERAU_WATCHLIST")
    if override:
        return Path(override)
    data = os.environ.get("CYBERAU_DATA_DIR")
    if not data:
        return None
    return Path(data).resolve().parent.parent / "watchlists" / "org-exposure.yaml"


def _watch_file() -> dict:
    path = _watchlist_path()
    if path is None or not path.is_file():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return raw if isinstance(raw, dict) else {}


def _supplier_names() -> list[str]:
    """Suppliers stay in the watchlist file. The shared model does not store them."""
    names: list[str] = []
    for item in _watch_file().get("suppliers") or []:
        if isinstance(item, str) and item.strip():
            names.append(item)
    return names


def _supplier_hit(text: str) -> bool:
    return any(_mentions(text, name) for name in _supplier_names())


def _loaded_watchlist() -> Watchlist | None:
    raw = _watch_file()
    if not raw:
        return None
    return Watchlist.model_validate(raw)


def _domains_allowed(domains: list[str]) -> str | None:
    if os.environ.get("CYBERAU_RF_ALLOW_EXTERNAL") == "1":
        return None
    watchlist = _loaded_watchlist()
    if watchlist is None:
        return None
    known = watchlist.known_subjects()
    blocked = [domain for domain in domains if domain.casefold() not in known]
    if blocked:
        return "domains must be on the org-exposure watchlist"
    return None


def _identity_body(extra: dict) -> dict:
    body = dict(extra)
    org = _org_id()
    if org:
        if "organization_id" not in body:
            body["organization_id"] = org
    return body


def _search_domains(domains: list[str], domain_type: str, limit: int, tool: str):
    body = _identity_body({"domains": domains, "domain_types": [domain_type], "limit": limit})
    return _request(
        "POST",
        f"{API}/identity/credentials/search",
        body=body,
        ttl=IDENTITY_TTL,
        tool=tool,
    )


def _detections(since: date | None, novel_only: bool, limit: int, domains: list[str], tool: str):
    filters: dict = {"novel_only": novel_only}
    if domains:
        filters["domains"] = domains
    if since is not None:
        filters["created"] = {"gte": _since_iso(since)}
    body: dict = {"filter": filters, "limit": limit}
    org = _org_id()
    if org:
        body["organization_id"] = [org]
    return _request(
        "POST",
        f"{API}/identity/detections",
        body=body,
        ttl=IDENTITY_TTL,
        tool=tool,
    )


def _count_identities(payload: dict, domains: list[str], domain_type: str) -> dict[str, int]:
    counts = {domain: 0 for domain in domains}
    identities = payload.get("identities")
    if not isinstance(identities, list):
        return counts
    attributed = False
    for item in identities:
        host = ""
        if isinstance(item, str) and "@" in item:
            host = item.rsplit("@", 1)[1]
        elif isinstance(item, dict):
            host = str(item.get("domain") or "")
        matched = ""
        for domain in domains:
            if host.casefold() == domain.casefold() or host.casefold().endswith(
                "." + domain.casefold()
            ):
                matched = domain
                break
        if not matched:
            continue
        counts[matched] = counts.get(matched, 0) + 1
        attributed = True
    if not attributed and len(domains) == 1 and isinstance(payload.get("count"), int):
        counts[domains[0]] = int(payload["count"])
    elif not identities and len(domains) == 1 and isinstance(payload.get("count"), int):
        counts[domains[0]] = int(payload["count"])
    return counts


def _family_name(value) -> str:
    if isinstance(value, dict):
        name = value.get("name")
        if isinstance(name, str):
            return name
    if isinstance(value, str):
        return value
    return ""


def _detection_domain(item: dict, domains: list[str]) -> str:
    service = item.get("authorization_service")
    host = ""
    if isinstance(service, dict):
        host = str(service.get("domain") or service.get("fqdn") or "")
    subject = item.get("subject")
    if not host and isinstance(subject, str) and "@" in subject:
        host = subject.rsplit("@", 1)[1]
    for domain in domains:
        folded = host.casefold()
        if folded == domain.casefold() or folded.endswith("." + domain.casefold()):
            return domain
    return domains[0] if len(domains) == 1 else ""


def rf_identity_exposure(
    domains: list[str],
    domain_types: list[str] | None = None,
    limit: int = 100,
) -> dict:
    """Counts of compromised identities. No passwords, cookies or usernames."""
    if not domains or len(domains) > 50:
        return _result([], "snapshot", warnings=("domains must contain 1 to 50 hosts",))
    if not _token():
        return _missing_token()
    blocked = _domains_allowed(domains)
    if blocked:
        return _result([], "snapshot", warnings=(blocked,))
    types = domain_types or ["Email", "Authorization"]
    unknown = [item for item in types if item not in {"Email", "Authorization"}]
    if unknown or not types:
        return _result([], "snapshot", warnings=("domain_types must be Email or Authorization",))
    if limit < 1 or limit > 1000:
        return _result([], "snapshot", warnings=("limit must be from 1 to 1000",))
    buckets = {
        domain: {"email": 0, "authorization": 0, "families": {}, "first": "", "last": ""}
        for domain in domains
    }
    states: list[str] = []
    urls = []
    warnings: list[str] = []
    for domain_type in types:
        payload, cache, warning, _response = _search_domains(
            domains, domain_type, limit, "rf_identity_exposure"
        )
        states.append(cache)
        urls.append(f"{API}/identity/credentials/search")
        if warning:
            warnings.append(warning)
            if warning.startswith("Blocked"):
                break
            continue
        if payload is None or not isinstance(payload.get("identities"), list):
            warnings.append("upstream payload was not usable")
            continue
        counts = _count_identities(payload, domains, domain_type)
        field = "email" if domain_type == "Email" else "authorization"
        for domain, count in counts.items():
            buckets[domain][field] += count
    if not any(item.startswith("Blocked") for item in warnings):
        payload, cache, warning, _response = _detections(
            None, False, limit, domains, "rf_identity_exposure"
        )
        states.append(cache)
        urls.append(f"{API}/identity/detections")
        if warning:
            warnings.append(warning)
        elif isinstance(payload, dict) and isinstance(payload.get("detections"), list):
            _merge_detection_times(buckets, payload, domains)
        else:
            warnings.append("upstream payload was not usable")
    rows = []
    for domain, bucket in buckets.items():
        if not (bucket["email"] or bucket["authorization"] or bucket["families"]):
            continue
        families = [
            {"name": untrusted_text(name, "recordedfuture"), "count": count}
            for name, count in sorted(bucket["families"].items())
        ]
        rows.append(
            {
                "domain": domain,
                "counts": {"email": bucket["email"], "authorization": bucket["authorization"]},
                "malware_families": families,
                "first_seen": bucket["first"] or None,
                "last_seen": bucket["last"] or None,
            }
        )
    return _result(rows, _combine(states), urls=urls, warnings=warnings)


def _merge_detection_times(buckets: dict, payload: dict, domains: list[str]) -> None:
    detections = payload.get("detections")
    if not isinstance(detections, list):
        return
    for item in detections:
        if not isinstance(item, dict):
            continue
        domain = _detection_domain(item, domains)
        if domain not in buckets:
            continue
        family = _family_name(item.get("malware_family"))
        if family:
            families = buckets[domain]["families"]
            families[family] = int(families.get(family, 0)) + 1
        seen = _time_text(item.get("created")) or ""
        if seen and (not buckets[domain]["first"] or seen < buckets[domain]["first"]):
            buckets[domain]["first"] = seen
        if seen and seen > buckets[domain]["last"]:
            buckets[domain]["last"] = seen


def rf_identity_detections(
    since: str | None = None,
    novel_only: bool = True,
    limit: int = 100,
) -> dict:
    """Novel identity detections grouped by domain and malware family."""
    if not _token():
        return _missing_token()
    day = _parse_day(since) if since else None
    if since and day is None:
        return _result([], "snapshot", warnings=("since must be YYYY-MM-DD",))
    if limit < 1 or limit > 1000:
        return _result([], "snapshot", warnings=("limit must be from 1 to 1000",))
    watchlist = _loaded_watchlist()
    domains = _watch_domains(watchlist) if watchlist else []
    payload, cache, warning, _response = _detections(
        day, bool(novel_only), limit, domains, "rf_identity_detections"
    )
    if warning:
        return _result([], cache, urls=[f"{API}/identity/detections"], warnings=(warning,))
    if not isinstance(payload, dict) or not isinstance(payload.get("detections"), list):
        return _result(
            [],
            cache,
            urls=[f"{API}/identity/detections"],
            warnings=("upstream payload was not usable",),
        )
    groups: dict[tuple[str, str], dict] = {}
    for item in payload["detections"]:
        if not isinstance(item, dict):
            continue
        if novel_only and item.get("novel") is False:
            continue
        domain = _detection_domain(item, domains) or _label(item.get("authorization_service"))
        family = _family_name(item.get("malware_family"))
        key = (domain, family)
        row = groups.setdefault(
            key,
            {
                "domain": domain,
                "malware_family": family,
                "count": 0,
                "first_seen": "",
                "last_seen": "",
            },
        )
        row["count"] += 1
        seen = _time_text(item.get("created")) or ""
        if seen and (not row["first_seen"] or seen < row["first_seen"]):
            row["first_seen"] = seen
        if seen and seen > row["last_seen"]:
            row["last_seen"] = seen
    data = []
    for row in groups.values():
        family = row["malware_family"]
        data.append(
            {
                "domain": row["domain"],
                "malware_family": untrusted_text(family, "recordedfuture") if family else None,
                "count": row["count"],
                "first_seen": row["first_seen"] or None,
                "last_seen": row["last_seen"] or None,
            }
        )
    return _result(data, cache, urls=[f"{API}/identity/detections"])


def rf_identity_lookup_hashed(emails_sha1: list[str]) -> dict:
    """Exposure history for SHA1 hashes of email addresses. Plain email is refused."""
    if not emails_sha1 or len(emails_sha1) > 100:
        return _result([], "snapshot", warnings=("emails_sha1 must contain 1 to 100 hashes",))
    hashes = []
    for value in emails_sha1:
        text = str(value).strip()
        if "@" in text or not re.fullmatch(r"[a-fA-F0-9]{40}", text):
            return _result(
                [],
                "snapshot",
                warnings=("rf_identity_lookup_hashed accepts SHA1 hex only, not a plain email",),
            )
        hashes.append(text.lower())
    if not _token():
        return _missing_token()
    body = _identity_body({"subjects_sha1": hashes})
    if "subjects" in body:
        body.pop("subjects")
    payload, cache, warning, _response = _request(
        "POST",
        f"{API}/identity/credentials/lookup",
        body=body,
        ttl=IDENTITY_TTL,
        tool="rf_identity_lookup_hashed",
    )
    url = f"{API}/identity/credentials/lookup"
    if warning:
        return _result([], cache, urls=[url], warnings=(warning,))
    if not isinstance(payload, dict):
        return _result([], cache, urls=[url], warnings=("upstream payload was not usable",))
    rows = []
    identities = payload.get("identities") if isinstance(payload.get("identities"), list) else []
    for index, item in enumerate(identities):
        digest = hashes[index] if index < len(hashes) else ""
        count = 0
        first = ""
        last = ""
        if isinstance(item, dict):
            if isinstance(item.get("count"), int):
                count = item["count"]
            credentials = item.get("credentials")
            if not isinstance(credentials, list):
                credentials = []
            if not count:
                count = len(credentials)
            for credential in credentials:
                if not isinstance(credential, dict):
                    continue
                for key in ("first_downloaded", "latest_downloaded"):
                    seen = credential.get(key)
                    if not isinstance(seen, str):
                        continue
                    if not first or seen < first:
                        first = seen
                    if seen > last:
                        last = seen
        if digest:
            rows.append(
                {
                    "sha1": digest,
                    "exposures": count,
                    "first_seen": first or None,
                    "last_seen": last or None,
                }
            )
    return _result(rows, cache, urls=[url])


def _playbook_search(
    categories: list[str],
    since: date | None,
    statuses: list[str] | None,
    limit: int,
):
    api_categories = [_SEARCH_CATEGORY[item] for item in categories]
    body: dict = {"category": api_categories, "limit": limit}
    if since is not None:
        body["created_range"] = {"from": _since_iso(since)}
    if statuses:
        body["statuses"] = statuses
    return _request(
        "POST",
        f"{API}/playbook-alert/search",
        body=body,
        ttl=PLAYBOOK_TTL,
        tool="rf_brand_alerts",
    )


def _alert_text(alert: dict) -> str:
    parts = [_label(alert.get("title")), _label(alert.get("entity"))]
    entities = alert.get("entity")
    if isinstance(entities, list):
        parts.extend(str(item) for item in entities if isinstance(item, str))
    return " ".join(part for part in parts if part)


def _normalise_alert(alert: dict, requested: list[str], watchlist: Watchlist | None) -> dict | None:
    if not isinstance(alert, dict):
        return None
    raw_category = _label(alert.get("category")) or str(alert.get("category") or "")
    tool_category = _FROM_API_CATEGORY.get(raw_category)
    if tool_category not in requested:
        return None
    text = _alert_text(alert)
    if tool_category == "third_party_risk":
        if not _supplier_hit(text):
            return None
        matched = None
        own = False
    else:
        matched = _matched_subject(text, watchlist) if watchlist else None
        own = bool(matched) if watchlist else True
    summary = _label(alert.get("title"))
    return {
        "alert_id": str(alert.get("playbook_alert_id") or alert.get("id") or ""),
        "category": tool_category,
        "priority": _label(alert.get("priority")),
        "status": _label(alert.get("status")),
        "summary": untrusted_text(summary, "recordedfuture") if summary else "",
        "ransomware": bool(_RANSOM.search(text)),
        "matched": matched is not None,
        "own_organisation": bool(own and matched is not None) if watchlist else own,
        "created": _time_text(alert.get("created")),
        "_raw_text": text,
        "_match": matched,
    }


def rf_brand_alerts(
    since: str | None = None,
    categories: list[str] | None = None,
    statuses: list[str] | None = None,
    limit: int = 50,
) -> dict:
    """Playbook alerts for brand, domain abuse and optional supplier categories."""
    if not _token():
        return _missing_token()
    day = _parse_day(since) if since else None
    if since and day is None:
        return _result([], "snapshot", warnings=("since must be YYYY-MM-DD",))
    chosen = categories or ["dark_web_brand", "domain_abuse"]
    unknown = [item for item in chosen if item not in _SEARCH_CATEGORY]
    if unknown:
        return _result([], "snapshot", warnings=("category is not supported",))
    if limit < 1 or limit > 250:
        return _result([], "snapshot", warnings=("limit must be from 1 to 250",))
    payload, cache, warning, _response = _playbook_search(chosen, day, statuses, limit)
    url = f"{API}/playbook-alert/search"
    if warning:
        return _result([], cache, urls=[url], warnings=(warning,))
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        return _result([], cache, urls=[url], warnings=("upstream payload was not usable",))
    watchlist = _loaded_watchlist()
    rows = []
    for item in payload["data"]:
        row = _normalise_alert(item, chosen, watchlist)
        if row is None:
            continue
        row.pop("_raw_text", None)
        row.pop("_match", None)
        rows.append(row)
    return _result(rows, cache, urls=[url])


def _scrub(value):
    had_image = False

    def walk(node, key_name: str = ""):
        nonlocal had_image
        if isinstance(node, dict):
            cleaned = {}
            for key, item in node.items():
                lowered = key.lower()
                if lowered in _DROP_KEYS or (
                    lowered in _IMAGE_KEYS and isinstance(item, str) and item.startswith("http")
                ):
                    had_image = had_image or lowered in _IMAGE_KEYS
                    continue
                cleaned[key] = walk(item, lowered)
            return cleaned
        if isinstance(node, list):
            return [walk(item, key_name) for item in node]
        if isinstance(node, str):
            if key_name in _IMAGE_KEYS and node.startswith("http"):
                had_image = True
                return None
            return untrusted_text(node, "recordedfuture")
        return node

    return walk(value), had_image


def _flatten_text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(_flatten_text(item) for item in value.values())
    if isinstance(value, list):
        return " ".join(_flatten_text(item) for item in value)
    return ""


def rf_alert_detail(category: str, alert_id: str) -> dict:
    """Detail panels for one playbook alert. Screenshots are not fetched."""
    if category not in _DETAIL_CATEGORIES:
        return _result([], "snapshot", warnings=("category is not supported",))
    if not alert_id or "/" in alert_id or ".." in alert_id:
        return _result([], "snapshot", warnings=("alert_id is not usable",))
    if not _token():
        return _missing_token()
    url = f"{API}/playbook-alert/{category}/{quote(alert_id, safe='')}"
    payload, cache, warning, _response = _request(
        "POST",
        url,
        body={},
        ttl=PLAYBOOK_TTL,
        tool="rf_alert_detail",
    )
    if warning:
        return _result([], cache, urls=[url], warnings=(warning,))
    if not isinstance(payload, dict):
        return _result([], cache, urls=[url], warnings=("upstream payload was not usable",))
    ransomware = bool(_RANSOM.search(_flatten_text(payload)))
    panels, _had_image = _scrub(payload.get("data") if "data" in payload else payload)
    return _result(
        {
            "alert_id": alert_id,
            "category": category,
            "ransomware": ransomware,
            "panels": panels,
            "screenshots": "not fetched",
        },
        cache,
        urls=[url],
    )


def rf_company_by_domain(domain: str) -> dict:
    """Company entity, risk score and top triggered rules for one domain."""
    if not domain or "/" in domain or " " in domain:
        return _result([], "snapshot", warnings=("domain is not usable",))
    if not _token():
        return _missing_token()
    blocked = _domains_allowed([domain])
    if blocked:
        return _result([], "snapshot", warnings=(blocked,))
    url = f"{API}/v2/company/by_domain/{quote(domain, safe='')}"
    payload, cache, warning, _response = _request(
        "GET",
        url,
        params={"fields": "risk"},
        ttl=PLAYBOOK_TTL,
        tool="rf_company_by_domain",
    )
    if warning:
        return _result([], cache, urls=[url], warnings=(warning,))
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
        return _result([], cache, urls=[url], warnings=("upstream payload was not usable",))
    data = payload["data"]
    entity = data.get("entity") if isinstance(data.get("entity"), dict) else {}
    risk = data.get("risk") if isinstance(data.get("risk"), dict) else {}
    rules = []
    details = risk.get("evidenceDetails")
    if isinstance(details, list):
        for item in details:
            if not isinstance(item, dict):
                continue
            name = item.get("rule") or item.get("name") or item.get("id")
            if isinstance(name, dict):
                name = name.get("name")
            if isinstance(name, str) and name:
                rules.append(untrusted_text(name, "recordedfuture"))
            if len(rules) >= 5:
                break
    name = entity.get("name") if isinstance(entity.get("name"), str) else ""
    return _result(
        {
            "domain": domain,
            "entity_id": entity.get("id") if isinstance(entity.get("id"), str) else "",
            "name": untrusted_text(name, "recordedfuture") if name else "",
            "risk_score": risk.get("score") if isinstance(risk.get("score"), int) else None,
            "criticality": risk.get("criticalityLabel")
            if isinstance(risk.get("criticalityLabel"), str)
            else "",
            "rules_triggered": risk.get("rules") if isinstance(risk.get("rules"), int) else None,
            "top_rules": rules,
        },
        cache,
        urls=[url],
    )


def rf_risklist_status(entity_type: str, risk_rule: str | None = None) -> dict:
    """Whether a risk list changed since the last stat check."""
    if entity_type not in {"ip", "domain", "hash", "url", "vulnerability"}:
        return _result([], "snapshot", warnings=("entity_type is not supported",))
    if not _token():
        return _missing_token()
    rule = risk_rule or "default"
    url = f"{API}/v2/{entity_type}/risklist"
    payload, cache, warning, response = _request(
        "HEAD",
        url,
        params={"list": rule},
        ttl=0,
        tool="rf_risklist_status",
        parse_json=False,
    )
    if warning:
        return _result([], cache, urls=[url], warnings=(warning,))
    etag = ""
    if response is not None:
        etag = str(response.headers.get("etag") or "")
    key = f"{entity_type}:{rule}"
    seen = _risk_seen()
    previous = seen.get(key) if isinstance(seen.get(key), str) else None
    changed = cache == "miss"
    if changed:
        seen[key] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        _save_risk_seen(seen)
    last_pulled = seen.get(key) or previous
    return _result(
        {
            "entity_type": entity_type,
            "risk_rule": rule,
            "changed": changed,
            "etag": etag,
            "last_pulled": last_pulled,
        },
        cache,
        urls=[url],
    )


def _risk_seen() -> dict:
    path = _data_dir() / _RISK_SEEN_NAME
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _save_risk_seen(seen: dict) -> None:
    path = _data_dir() / _RISK_SEEN_NAME
    path.write_text(json.dumps(seen), encoding="utf-8")


def _kind_for_detection(item: dict) -> str:
    source = _label(item.get("source_type"))
    if source in {"DatabaseDumps", "DatabaseCombolists"}:
        return "breach_credential"
    return "infostealer_credential"


def _finding(
    *,
    kind: str,
    subject_type: str,
    subject_value: str,
    observed: datetime,
    source_ref: str,
    counts: dict[str, int] | None = None,
    confidence: str = "vendor_reported",
    personal: bool = False,
    first: datetime | None = None,
) -> ExposureFinding:
    finding = ExposureFinding(
        finding_id=finding_id("recordedfuture", kind, subject_value, source_ref),
        vendor="recordedfuture",
        kind=kind,
        subject=Subject(type=subject_type, value=subject_value, watchlist_entry=subject_value),
        observed_at=observed,
        first_seen=first or observed,
        licence_scope="store_metadata",
        confidence=confidence,
        counts=counts,
        data_classes=["email address"] if personal else None,
        source_ref=source_ref,
        stix_exportable=False,
        contains_personal_information=personal,
    )
    return clamp_to_terms(canonical_finding(finding), _terms())


def _risk_scores(domains: list[str]) -> dict[str, int]:
    scores = {}
    for domain in domains:
        payload, _cache, warning, _response = _request(
            "GET",
            f"{API}/v2/company/by_domain/{quote(domain, safe='')}",
            params={"fields": "risk"},
            ttl=PLAYBOOK_TTL,
            tool="rf_company_by_domain",
        )
        if warning and warning.startswith("Blocked"):
            break
        if not isinstance(payload, dict):
            continue
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        risk = data.get("risk") if isinstance(data.get("risk"), dict) else {}
        if isinstance(risk.get("score"), int):
            scores[domain] = risk["score"]
    return scores


def _apply_score(finding: ExposureFinding, scores: dict[str, int]) -> ExposureFinding:
    score = scores.get(finding.subject.value)
    if score is None:
        return finding
    counts = dict(finding.counts or {})
    counts["risk_score"] = score
    return finding.model_copy(update={"counts": counts})


class RecordedFutureConnector(PremiumConnector):
    """Recorded Future premium connector. Read-only, off until the user enables it."""

    last_warnings: tuple[str, ...] = ()

    def __init__(self) -> None:
        spec = _vendor()
        super().__init__(
            key="recorded-future",
            server_name="recordedfuture",
            attribution=spec.terms.attribution,
            tools=[
                ToolSpec(
                    "rf_identity_exposure",
                    "Counts of compromised identities for watchlist domains. "
                    "No passwords, cookies or usernames.",
                    rf_identity_exposure,
                ),
                ToolSpec(
                    "rf_identity_detections",
                    "Novel identity detections grouped by domain and malware family.",
                    rf_identity_detections,
                ),
                ToolSpec(
                    "rf_identity_lookup_hashed",
                    "Exposure history for SHA1 hashes of email addresses.",
                    rf_identity_lookup_hashed,
                ),
                ToolSpec(
                    "rf_brand_alerts",
                    "Dark web brand and domain abuse playbook alerts.",
                    rf_brand_alerts,
                ),
                ToolSpec(
                    "rf_alert_detail",
                    "Detail panels for one playbook alert. Screenshots are not fetched.",
                    rf_alert_detail,
                ),
                ToolSpec(
                    "rf_company_by_domain",
                    "Company entity, risk score and top triggered rules for a domain.",
                    rf_company_by_domain,
                ),
                ToolSpec(
                    "rf_risklist_status",
                    "Whether a risk list changed since the last stat check.",
                    rf_risklist_status,
                ),
            ],
            vendor=spec.server,
            licence_env=tuple(spec.licence_env),
            terms=spec.terms,
            quota=spec.quota,
        )

    def exposure_for(
        self,
        watchlist: Watchlist,
        since: date,
        *,
        routine: bool = False,
    ) -> list[ExposureFinding]:
        global _ROUTINE
        previous = _ROUTINE
        _ROUTINE = routine
        self.last_warnings = ()
        findings: list[ExposureFinding] = []
        warnings: list[str] = []
        try:
            findings.extend(self._identity_findings(watchlist, since, warnings))
            findings.extend(self._alert_findings(watchlist, since, warnings))
            if not any(item.startswith("Blocked") for item in warnings):
                scores = _risk_scores(_watch_domains(watchlist))
                findings = [_apply_score(item, scores) for item in findings]
        finally:
            _ROUTINE = previous
        self.last_warnings = tuple(warnings)
        return findings

    def _identity_findings(self, watchlist: Watchlist, since: date, warnings: list[str]):
        domains = _watch_domains(watchlist)
        if not domains:
            return []
        found = []
        totals = {domain: {"email": 0, "authorization": 0} for domain in domains}
        for domain_type, field in (("Email", "email"), ("Authorization", "authorization")):
            payload, _cache, warning, _response = _search_domains(
                domains, domain_type, 100, "rf_identity_exposure"
            )
            if warning:
                warnings.append(warning)
                if warning.startswith("Blocked"):
                    return found
                continue
            if not isinstance(payload, dict):
                warnings.append("upstream payload was not usable")
                continue
            for domain, count in _count_identities(payload, domains, domain_type).items():
                totals[domain][field] += count
        for domain, counts in totals.items():
            if not counts["email"] and not counts["authorization"]:
                continue
            found.append(
                _finding(
                    kind="infostealer_credential",
                    subject_type="email_domain" if domain in watchlist.email_domains else "domain",
                    subject_value=domain,
                    observed=datetime.now(UTC),
                    source_ref=f"identity-search:{domain}",
                    counts=counts,
                    personal=True,
                )
            )
        payload, _cache, warning, _response = _detections(
            since, True, 100, domains, "rf_identity_detections"
        )
        if warning:
            warnings.append(warning)
            return found
        detections = payload.get("detections") if isinstance(payload, dict) else None
        if not isinstance(detections, list):
            warnings.append("upstream payload was not usable")
            return found
        for item in detections:
            if not isinstance(item, dict):
                continue
            if item.get("novel") is False:
                continue
            domain = _detection_domain(item, domains)
            if not domain:
                continue
            personal = isinstance(item.get("subject"), str) and "@" in item["subject"]
            found.append(
                _finding(
                    kind=_kind_for_detection(item),
                    subject_type="email_domain",
                    subject_value=domain,
                    observed=_parse_dt(item.get("created")),
                    source_ref=str(item.get("id") or f"detection:{domain}"),
                    counts={"records": 1},
                    personal=personal,
                )
            )
        return found

    def _alert_findings(self, watchlist: Watchlist, since: date, warnings: list[str]):
        payload, _cache, warning, _response = _playbook_search(
            ["dark_web_brand", "domain_abuse"],
            since,
            None,
            50,
        )
        if warning:
            warnings.append(warning)
            return []
        rows = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            warnings.append("upstream payload was not usable")
            return []
        found = []
        for item in rows:
            row = _normalise_alert(item, ["dark_web_brand", "domain_abuse"], watchlist)
            if row is None or not row.get("own_organisation"):
                continue
            match = row.get("_match")
            if not match:
                continue
            subject_type, subject_value = match
            text = row.get("_raw_text") or ""
            if row["category"] == "domain_abuse":
                kind = "typosquat_domain"
            elif row["ransomware"] or _RANSOM.search(text):
                kind = "leak_site_claim"
            else:
                kind = "dark_web_mention"
            found.append(
                _finding(
                    kind=kind,
                    subject_type=subject_type,
                    subject_value=subject_value,
                    observed=_parse_dt(row.get("created")),
                    source_ref=row["alert_id"] or "playbook",
                    confidence="vendor_reported",
                )
            )
        return found

    def raise_new_alerts(
        self,
        watchlist: Watchlist,
        since: date,
        store: ExposureStore,
    ) -> list[ExposureFinding]:
        """Store findings and return each new detection or playbook alert once."""
        alerts = []
        for finding in self.exposure_for(watchlist, since, routine=True):
            if (finding.source_ref or "").startswith("identity-search:"):
                store.write(finding, terms=self.terms, watchlist=watchlist)
                continue
            if finding.kind not in _ALERT_KINDS:
                continue
            status = store.write(finding, terms=self.terms, watchlist=watchlist)
            if status == "stored":
                alerts.append(finding)
        return alerts

    def health(self, *, live: bool = False, check_schema: bool = False) -> Probe:
        if check_schema:
            problem = schema_drift(load_schema_samples())
            if problem:
                return Probe(self.key, False, problem)
            if not live:
                return Probe(self.key, True, "schema ok")
        basic = self.health_result(live=False)
        if not basic.configured:
            return Probe(self.key, True, basic.detail)
        if not live:
            return Probe(self.key, True, "offline ok")
        problem = _live_probe()
        if problem:
            return Probe(self.key, False, problem)
        return Probe(self.key, True, "live ok")


def _live_probe() -> str:
    checks = (
        (
            "POST",
            f"{API}/identity/detections",
            {"filter": {"novel_only": True}, "limit": 1},
            None,
            "rf_identity_detections",
        ),
        (
            "POST",
            f"{API}/playbook-alert/search",
            {"category": ["domain_abuse"], "limit": 1},
            None,
            "rf_brand_alerts",
        ),
        (
            "HEAD",
            f"{API}/v2/domain/risklist",
            None,
            {"list": "default"},
            "rf_risklist_status",
        ),
    )
    for method, url, body, params, tool in checks:
        _payload, _cache, warning, _response = _request(
            method,
            url,
            body=body,
            params=params,
            ttl=60,
            tool=tool,
            parse_json=method != "HEAD",
        )
        if warning:
            return warning
    return ""


def schema_drift(samples: dict) -> str | None:
    search = samples.get("identity_search")
    if not isinstance(search, dict) or "identities" not in search:
        return "schema drift, missing identities"
    detections = samples.get("detections")
    if not isinstance(detections, dict) or not isinstance(detections.get("detections"), list):
        return "schema drift, missing detections"
    playbook = samples.get("playbook_search")
    if not isinstance(playbook, dict) or not isinstance(playbook.get("data"), list):
        return "schema drift, missing data"
    company = samples.get("company") if isinstance(samples.get("company"), dict) else {}
    data = company.get("data") if isinstance(company.get("data"), dict) else {}
    entity = data.get("entity") if isinstance(data.get("entity"), dict) else {}
    risk = data.get("risk") if isinstance(data.get("risk"), dict) else {}
    if "id" not in entity:
        return "schema drift, missing id"
    if "score" not in risk:
        return "schema drift, missing score"
    detail = samples.get("alert_detail")
    if not isinstance(detail, dict) or "data" not in detail:
        return "schema drift, missing data"
    return None


def load_schema_samples() -> dict:
    override = os.environ.get("CYBERAU_RF_SCHEMA_FIXTURE")
    path = Path(override) if override else _SAMPLES
    return json.loads(path.read_text(encoding="utf-8"))


def load_mcp_tool_names() -> list[str]:
    if not _MCP_TOOLS.is_file():
        return ["whoami"]
    payload = json.loads(_MCP_TOOLS.read_text(encoding="utf-8"))
    tools = payload.get("tools") if isinstance(payload, dict) else payload
    names = []
    for item in tools or []:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict) and isinstance(item.get("name"), str):
            names.append(item["name"])
    return names


def included_mcp_tools(names: list[str] | None = None) -> list[str]:
    """Read tools only. Update, create and takedown tools stay excluded."""
    chosen = names if names is not None else load_mcp_tool_names()
    kept = []
    for name in chosen:
        lowered = name.casefold()
        if any(marker in lowered for marker in _WRITE_MARKERS):
            continue
        kept.append(name)
    return sorted(set(kept))


def render_official_mcp(*, enabled: bool = False) -> dict:
    """Official MCP entry. A present client id does not switch it on."""
    return {
        "url": "https://mcp.recordedfuture.com/mcp",
        "auth": "oauth",
        "enabled": bool(enabled),
        "trust": "untrusted",
        "lazy": True,
        "timeout": 120,
        "tools": {"include": included_mcp_tools()},
    }


def mcp_doctor(*, enabled: bool, whoami: dict | None = None) -> str:
    if not enabled:
        return "off by default: licence terms (docs/connectors/recorded-future.md)"
    org = _whoami_org(whoami or {})
    if not org:
        return "on, organisation not confirmed via whoami"
    return f"connected organisation: {org}"


def _whoami_org(payload: dict) -> str:
    for key in ("organisation", "organization", "org_name"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    data = payload.get("data")
    if isinstance(data, dict):
        return _whoami_org(data)
    return ""


def note_mcp_invocation(name: str, *, routine: bool = False) -> dict:
    """Count one MCP tool call as one API call. Write tools are refused."""
    if name not in included_mcp_tools():
        return {"ok": False, "counted": False, "reason": "excluded"}
    if _CONFIG is None or _LEDGER is None:
        return {"ok": False, "counted": False, "reason": "no budget config"}
    before = _LEDGER.usage("recordedfuture").calls_today
    decision = pre_tool_call(
        tool_name=name,
        vendor="recordedfuture",
        routine=routine,
        config=_CONFIG,
        ledger=_LEDGER,
    )
    after = _LEDGER.usage("recordedfuture").calls_today
    return {
        "ok": not decision["block"],
        "counted": after == before + 1,
        "message": decision["message"],
    }


def connector() -> RecordedFutureConnector:
    return RecordedFutureConnector()


register_connector("recorded-future", connector)
