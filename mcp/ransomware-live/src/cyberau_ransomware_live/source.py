"""Read-only ransomware.live victim claims for Australia."""

import hashlib
import json
import os
import re
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Annotated
from zoneinfo import ZoneInfo

import yaml
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from pydantic import Field

PRO_VICTIMS = "https://api-pro.ransomware.live/victims/"
V2_RECENT = "https://api.ransomware.live/v2/recentvictims"
ATTRIBUTION = (
    "ransomware.live. Victim entries are leak-site claims, not confirmed incidents. "
    "Free community project; check the site terms before redistributing."
)
DOCTOR_NOTE = "off by default: licence terms"
TERMS = (
    "Victim entries are claims scraped from criminal leak sites, not confirmed incidents. "
    "Store metadata only. Do not export victim names as STIX or redistribute them."
)
_SYDNEY = ZoneInfo("Australia/Sydney")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_Date = Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")]
_Limit = Annotated[int, Field(ge=1, le=500)]
_Days = Annotated[int, Field(ge=1, le=90)]
_PACKAGE = Path(__file__).resolve().parents[2]
_TRANSPORT = None
# One poll an hour on average. The burst covers retries of that same poll.
POLL_RATE = 1 / 3600
POLL_BURST = 4
_CACHE_TTL = 3600
_SOURCE = "ransomlive"
_STALE_NOTE = "live fetch failed; served from a stale cached copy"
_UNUSABLE = "ransomware.live response was not usable"
_SNAPSHOT_NOTE = "served from the bundled synthetic snapshot, not live data"


def ransom_au_victims(
    since: _Date | None = None,
    sector: str | None = None,
    group: str | None = None,
    limit: _Limit = 50,
) -> dict:
    problem = _validate_victims(since, limit)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    payload, cache, warning = _query(sector=sector or None, group=group or None)
    if payload is None:
        return _envelope([], cache, warnings=(warning or _UNUSABLE,))
    notes = (warning,) if warning else ()
    rows, metas, problem = _claims(
        payload,
        since=since,
        sector=sector or None,
        group=group or None,
        limit=limit,
    )
    if problem and not rows:
        return _envelope([], cache, warnings=(*notes, problem))
    _persist(metas, cache)
    if not rows:
        notes = (*notes, "no matching Australian claim")
    return _envelope(rows, cache, warnings=notes)


def ransom_watchlist_match(days: _Days = 7) -> dict:
    problem = _validate_days(days)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    watch, problem = _load_watchlist()
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    payload, cache, warning = _query(sector=None, group=None)
    if payload is None:
        return _envelope([], cache, warnings=(warning or _UNUSABLE,))
    notes = (warning,) if warning else ()
    rows, metas, problem = _claims(payload, since=None, sector=None, group=None, limit=500)
    if problem and not rows:
        return _envelope([], cache, warnings=(*notes, problem))
    matched = _match(rows, metas, watch or {}, days)
    _persist([item[1] for item in matched], cache)
    if not matched:
        return _envelope(
            [], cache, warnings=(*notes, "no claim matched the org exposure watchlist")
        )
    return _envelope([item[0] for item in matched], cache, warnings=notes)


def connector() -> Connector:
    return _RansomLiveConnector()


class _RansomLiveConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="ransomware-live",
            server_name="ransomlive",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "ransom_au_victims",
                    "Leak-site claims naming Australian organisations, newest first. "
                    "Each record is an unverified claim, not a confirmed incident.",
                    ransom_au_victims,
                ),
                ToolSpec(
                    "ransom_watchlist_match",
                    "Match recent leak-site claims against the org-exposure watchlist. "
                    "Claims are unverified. State the terms before the first call.",
                    ransom_watchlist_match,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            payload = _load(_snapshot_text())
            problem = schema_drift(payload)
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        payload, cache, warning = _query(sector=None, group=None, force_live=True)
        if warning:
            return Probe(self.key, False, warning)
        if cache != "miss":
            return Probe(self.key, False, f"live probe was answered from {cache}, not the service")
        problem = schema_drift(payload)
        if problem:
            return Probe(self.key, False, problem)
        if not _raw_rows(payload):
            return Probe(self.key, False, "live probe returned no victims")
        return Probe(self.key, True, "live ok")


def schema_drift(payload) -> str | None:
    rows = _raw_rows(payload)
    if rows is None:
        return "ransomware.live payload has no victim list"
    if not rows:
        return None
    first = rows[0]
    if not isinstance(first, dict):
        return "ransomware.live schema drift, victim is not an object"
    if "victim" not in first and "post_title" not in first:
        return "ransomware.live schema drift, missing victim"
    if "group" not in first and "group_name" not in first:
        return "ransomware.live schema drift, missing group"
    if "country" not in first:
        return "ransomware.live schema drift, missing country"
    return None


def enabled_for_profile(catalog: dict, *, user_enabled: bool | None) -> bool:
    """Catalog default is off. A profile value is kept across updates."""
    if user_enabled is not None:
        return user_enabled
    return bool(catalog.get("enabled_by_default"))


def _validate_victims(since: str | None, limit: int) -> str:
    if since:
        if _DATE.fullmatch(since) is None:
            return "since must be YYYY-MM-DD"
        try:
            date.fromisoformat(since)
        except ValueError:
            return "since must be YYYY-MM-DD"
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        return "limit must be between 1 and 500"
    return ""


def _validate_days(days: int) -> str:
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 90:
        return "days must be between 1 and 90"
    return ""


def _query(
    *,
    sector: str | None,
    group: str | None,
    force_live: bool = False,
) -> tuple[object | None, str, str]:
    secret = lookup("RANSOMWARE_LIVE_API_KEY")
    if secret:
        params: dict[str, str] = {"country": "AU"}
        if sector:
            params["sector"] = sector
        if group:
            params["group"] = group
        return _fetch(
            PRO_VICTIMS,
            params,
            headers={"X-API-KEY": secret},
            force_live=force_live,
        )
    return _fetch(V2_RECENT, {}, headers=None, force_live=force_live)


def _fetch(
    url: str,
    params: dict,
    *,
    headers: dict | None,
    force_live: bool,
) -> tuple[object | None, str, str]:
    snapshot = os.environ.get("CYBERAU_RANSOMLIVE_SNAPSHOT")
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    if snapshot and not force_live:
        return _load(_snapshot_text()), "snapshot", "served from a snapshot file, not live data"
    data_dir = _data_dir()
    cache = HttpCache(data_dir / "http_cache.sqlite")
    cache_key = cache.key("GET", url, params, b"", "anonymous")
    cached = cache.get(cache_key)
    if cached and not force_live and (offline or cache.fresh(cached)):
        if cache.fresh(cached):
            return _load_bytes(cached.body), "hit", ""
        return _load_bytes(cached.body), "stale", "offline; served from a stale cached copy"
    if offline:
        return _load(_snapshot_text()), "snapshot", f"offline with no cached copy; {_SNAPSHOT_NOTE}"
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    client = HttpClient(
        "ransomware-live",
        policy=EgressPolicy(allowlist, "ransomware-live"),
        cache=cache,
        limiter=RateLimiter(data_dir / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=POLL_RATE,
        burst=POLL_BURST,
        window="rolling",
        retries=1,
        transport=_TRANSPORT,
    )
    try:
        try:
            response = client.get(
                url,
                params=params or None,
                headers=headers,
                ttl=_CACHE_TTL,
                skip_cache=force_live,
            )
        except Exception as exc:
            return _after_error(exc, cache, cache_key, force_live=force_live)
        if response.status in (401, 403):
            return None, "miss", _auth_warning(response.status)
        if response.status == 429:
            return _after_limit(cache, cache_key, force_live=force_live)
        if response.status >= 400:
            return None, "snapshot", f"ransomware.live returned {response.status}"
        if response.cache == "stale":
            return _load_bytes(response.body), "stale", _STALE_NOTE
        return _load_bytes(response.body), response.cache, ""
    finally:
        client.close()


def _after_error(exc: Exception, cache: HttpCache, cache_key: str, *, force_live: bool):
    message = _safe(exc)
    if force_live or isinstance(exc, EgressDenied):
        return None, "snapshot", message
    cached = cache.get(cache_key)
    if cached:
        return _load_bytes(cached.body), "stale", f"{_STALE_NOTE} ({message})"
    return None, "snapshot", f"ransomware.live unavailable: {message}"


def _after_limit(cache: HttpCache, cache_key: str, *, force_live: bool):
    if not force_live:
        cached = cache.get(cache_key)
        if cached:
            return _load_bytes(cached.body), "stale", f"{_STALE_NOTE} (rate limited)"
    return None, "snapshot", "ransomware.live rate limited; retry later"


def _auth_warning(status: int) -> str:
    return f"ransomware.live returned {status}; check RANSOMWARE_LIVE_API_KEY"


def _claims(
    payload,
    *,
    since: str | None,
    sector: str | None,
    group: str | None,
    limit: int,
) -> tuple[list[dict], list[dict], str]:
    problem = schema_drift(payload)
    if problem:
        return [], [], problem
    start = date.fromisoformat(since) if since else None
    chosen: list[tuple[date, dict, dict]] = []
    for raw in _raw_rows(payload) or []:
        if str(raw.get("country", "")).upper() != "AU":
            continue
        if sector and _plain(raw, "activity", "sector").casefold() != sector.casefold():
            continue
        if group and _plain(raw, "group", "group_name").casefold() != group.casefold():
            continue
        when = _when(raw)
        if start and (when is None or when < start):
            continue
        record, meta = _record(raw)
        chosen.append((when or date.min, record, meta))
    chosen.sort(key=lambda item: (item[0], _sort_name(item[1])), reverse=True)
    picked = chosen[:limit]
    return [item[1] for item in picked], [item[2] for item in picked], ""


def _record(raw: dict) -> tuple[dict, dict]:
    victim = _plain(raw, "victim", "post_title")
    gang = _plain(raw, "group", "group_name")
    sector = _plain(raw, "activity", "sector")
    website = _plain(raw, "website", "domain")
    description = _plain(raw, "description")
    discovered_on = _as_sydney_date(str(raw.get("discovered") or ""))
    discovered = discovered_on.isoformat() if discovered_on else ""
    attacked = _as_sydney_date(str(raw.get("attackdate") or raw.get("published") or ""))
    record = {
        "victim": _wrap(victim),
        "group": _wrap(gang),
        "country": "AU",
        "sector": _wrap(sector),
        "website": _wrap(website),
        "discovered": discovered,
        "attackdate": attacked.isoformat() if attacked else "",
        "claim": "unverified",
        "note": _wrap("Leak-site claim, not a confirmed incident."),
    }
    if description:
        record["description"] = _wrap(description)
    identity = f"{victim}|{gang}|{discovered}"
    meta = {
        "record_id": hashlib.sha256(identity.encode()).hexdigest()[:16],
        "country": "AU",
        "group": gang,
        "sector": sector,
        "discovered": discovered,
        "attackdate": record["attackdate"],
        "claim": "unverified",
    }
    return record, meta


def _match(rows: list[dict], metas: list[dict], watch: dict, days: int):
    targets = _targets(watch)
    if not targets:
        return []
    earliest = _today() - timedelta(days=days)
    matched = []
    for record, meta in zip(rows, metas, strict=True):
        when = _as_sydney_date(record.get("discovered") or "") or _as_sydney_date(
            record.get("attackdate") or ""
        )
        if when is None or when < earliest:
            continue
        found = _hit(record, targets)
        if found is None:
            continue
        kind, value = found
        matched.append(
            (
                {
                    **record,
                    "matched_on": kind,
                    "watchlist_entry": _wrap(value),
                },
                meta,
            )
        )
    return matched


def _hit(record: dict, targets: list[tuple[str, str]]) -> tuple[str, str] | None:
    host = _host(_unwrap(record.get("website") or ""))
    victim = _unwrap(record.get("victim") or "").casefold()
    for kind, value in targets:
        if kind == "domain" and host and (host == value or host.endswith("." + value)):
            return kind, value
    for kind, value in targets:
        if kind in {"name", "brand"} and value.casefold() in victim:
            return kind, value
    return None


def _targets(watch: dict) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    organisation = watch.get("organisation") or watch.get("organization")
    if isinstance(organisation, str) and organisation.strip():
        found.append(("name", organisation.strip()))
    for brand in watch.get("brands") or []:
        if isinstance(brand, str) and len(brand.strip()) >= 3:
            found.append(("brand", brand.strip()))
    domains = list(watch.get("domains") or []) + list(watch.get("email_domains") or [])
    for domain in domains:
        if isinstance(domain, str) and domain.strip():
            found.append(("domain", domain.strip().lower()))
    for subsidiary in watch.get("subsidiaries") or []:
        if not isinstance(subsidiary, dict):
            continue
        name = subsidiary.get("name")
        if isinstance(name, str) and name.strip():
            found.append(("name", name.strip()))
        for domain in subsidiary.get("domains") or []:
            if isinstance(domain, str) and domain.strip():
                found.append(("domain", domain.strip().lower()))
    excluded = {str(item).casefold() for item in (watch.get("exclude") or []) if str(item).strip()}
    return [item for item in found if item[1].casefold() not in excluded]


def _load_watchlist() -> tuple[dict | None, str]:
    path = next((item for item in _watchlist_candidates() if item.is_file()), None)
    if path is None:
        return None, "org exposure watchlist was not found"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        return None, "org exposure watchlist was not usable"
    if not isinstance(data, dict):
        return None, "org exposure watchlist was not usable"
    if not _targets(data):
        return None, "org exposure watchlist has no names, brands or domains"
    return data, ""


def _watchlist_candidates() -> list[Path]:
    override = os.environ.get("CYBERAU_ORG_WATCHLIST")
    if override:
        return [Path(override)]
    data = _data_dir()
    found = [
        data / "watchlists" / "org-exposure.yaml",
        data / "watchlists.yaml",
    ]
    if data.name == "cyber-au" and data.parent.name == "plugin-data":
        found.append(data.parents[1] / "watchlists" / "org-exposure.yaml")
    return found


def _persist(rows: list[dict], cache: str) -> None:
    """Append metadata for claims not stored yet. A snapshot is never real feed history."""
    if not rows or cache == "snapshot":
        return
    directory = _data_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "ransomlive-metadata.jsonl"
    seen: set[str] = set()
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                seen.add(json.loads(line)["record_id"])
            except (ValueError, KeyError, TypeError):
                continue
    with path.open("a", encoding="utf-8") as handle:
        for row in rows:
            if row["record_id"] in seen:
                continue
            seen.add(row["record_id"])
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _envelope(data, cache: str, warnings: tuple[str, ...] = ()) -> dict:
    return envelope(
        "ransomware-live",
        data,
        urls=[PRO_VICTIMS, V2_RECENT],
        cache=cache,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _plain(raw: dict, *names: str) -> str:
    for name in names:
        value = raw.get(name)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _when(raw: dict) -> date | None:
    discovered = _as_sydney_date(str(raw.get("discovered") or ""))
    if discovered:
        return discovered
    return _as_sydney_date(str(raw.get("attackdate") or raw.get("published") or ""))


def _today() -> date:
    override = os.environ.get("CYBERAU_RANSOMLIVE_TODAY")
    if override:
        return date.fromisoformat(override)
    return datetime.now(_SYDNEY).date()


def _as_sydney_date(value: str) -> date | None:
    text = value.strip()
    if not text or text.lower() == "none":
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        if _DATE.match(text[:10]):
            try:
                return date.fromisoformat(text[:10])
            except ValueError:
                return None
        return None
    if parsed.tzinfo is None:
        return parsed.date()
    return parsed.astimezone(_SYDNEY).date()


def _host(website: str) -> str:
    text = website.strip().lower()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0].split(":", 1)[0]
    if text.startswith("www."):
        text = text[4:]
    return text


def _wrap(value: str) -> str:
    if not value:
        return ""
    return untrusted_text(value, _SOURCE)


def _unwrap(value: str) -> str:
    prefix = f"<<untrusted source={_SOURCE}>> "
    suffix = " <<end untrusted>>"
    if value.startswith(prefix) and value.endswith(suffix):
        return value[len(prefix) : -len(suffix)]
    return value


def _sort_name(record: dict) -> str:
    return _unwrap(record.get("victim") or "").casefold()


def _raw_rows(payload) -> list | None:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("victims", "data", "results"):
            rows = payload.get(key)
            if isinstance(rows, list):
                return rows
    return None


def _load(text: str):
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, (dict, list)):
        return payload
    return None


def _load_bytes(body: bytes):
    try:
        return _load(body.decode("utf-8"))
    except UnicodeDecodeError:
        return None


def _snapshot_text() -> str:
    snapshot = os.environ.get("CYBERAU_RANSOMLIVE_SNAPSHOT")
    path = Path(snapshot) if snapshot else _PACKAGE / "data" / "victims_au.json"
    return path.read_text(encoding="utf-8")


def _data_dir() -> Path:
    return Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-ransomlive"))


def _safe(exc: Exception) -> str:
    message = redact(str(exc))
    secret = lookup("RANSOMWARE_LIVE_API_KEY")
    if secret:
        message = message.replace(secret, "[REDACTED]")
    return message


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("ransomware-live", connector)
