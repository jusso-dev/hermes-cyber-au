"""Read-only AlienVault OTX indicators and subscribed pulses."""

import hashlib
import ipaddress
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import quote, urlsplit
from zoneinfo import ZoneInfo

import jsonschema
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimited, RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from pydantic import Field

API_ROOT = "https://otx.alienvault.com/api/v1"
PULSES_URL = f"{API_ROOT}/pulses/subscribed"
HOST = "otx.alienvault.com"
ATTRIBUTION = (
    "OTX terms of service. Pulses are community content and must be treated as untrusted text."
)
INDICATOR_TTL = 6 * 3600
PULSE_TTL = 3600
_TYPES = ("IPv4", "IPv6", "domain", "hostname", "url", "file")
_IndicatorType = Literal["IPv4", "IPv6", "domain", "hostname", "url", "file"]
_Date = Annotated[
    str,
    Field(
        pattern=r"^\d{4}-\d{2}-\d{2}$", description="YYYY-MM-DD, interpreted in Australia/Sydney"
    ),
]
_Limit = Annotated[int, Field(ge=1, le=100)]
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SECTION = re.compile(r"^[A-Za-z0-9_]{1,40}$")
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})$"
)
_HASH = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")
_SECTION_MARKERS = {
    "reputation": ("reputation",),
    "geo": ("country_code", "country_name", "asn", "latitude", "city"),
    "malware": ("data",),
    "url_list": ("url_list",),
    "passive_dns": ("passive_dns",),
}
_PACKAGE = Path(__file__).resolve().parents[2]
_SYDNEY = ZoneInfo("Australia/Sydney")
_UTC = ZoneInfo("UTC")
_TRANSPORT = None
_MAX_PAGES = 5
_TLP = {"", "white", "clear", "green", "amber", "amber+strict", "red"}


def otx_indicator(
    type: _IndicatorType,
    value: str,
    section: str = "general",
) -> dict:
    kind = type
    problem = _validate_indicator(kind, value, section)
    if problem:
        return _envelope(None, "snapshot", warnings=(problem,))
    url = _indicator_url(kind, value, section)
    payload, cache, warning = _fetch(url, None, ttl=INDICATOR_TTL)
    if warning:
        return _envelope(None, cache, [url], warnings=(warning,))
    if payload is None:
        return _envelope(None, cache, [url], warnings=("OTX payload was not usable",))
    problem = _indicator_problem(section, payload)
    if problem:
        return _envelope(None, cache, [url], warnings=(problem,))
    found = payload.get("indicator")
    if cache == "snapshot":
        if section != "general" or not _same_indicator(kind, found, value):
            note = "no matching indicator in the offline snapshot or cache"
            return _envelope(None, cache, [url], warnings=(note,))
    elif (section == "general" or found is not None) and not _same_indicator(kind, found, value):
        return _envelope(None, cache, [url], warnings=("OTX returned a different indicator",))
    record = _indicator_record(payload, kind, value, section)
    if cache != "snapshot":
        _persist([_indicator_observation(record)])
    return _envelope(record, cache, [url], _latest([item["modified"] for item in record["pulses"]]))


def otx_pulses(modified_since: _Date | None = None, limit: _Limit = 20) -> dict:
    problem = _validate_pulses(modified_since, limit)
    if problem:
        return _envelope([], "snapshot", [PULSES_URL], warnings=(problem,))
    params = _pulse_params(modified_since, limit)
    payload, cache, warning = _fetch(PULSES_URL, params, ttl=PULSE_TTL)
    if warning:
        return _envelope([], cache, [PULSES_URL], warnings=(warning,))
    if payload is None:
        return _envelope([], cache, [PULSES_URL], warnings=("OTX payload was not usable",))
    rows, warning = _gather_pulses(payload, cache, modified_since, limit)
    if warning and not rows:
        return _envelope([], cache, [PULSES_URL], warnings=(warning,))
    warnings = (warning,) if warning else ()
    if cache != "snapshot":
        _persist([_pulse_observation(row) for row in rows])
    return _envelope(
        rows, cache, [PULSES_URL], _latest([row["modified"] for row in rows]), warnings
    )


def connector() -> Connector:
    return _OtxConnector()


class _OtxConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="otx",
            server_name="otx",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec("otx_indicator", "Indicator details from one OTX section.", otx_indicator),
                ToolSpec("otx_pulses", "Subscribed pulses modified since a date.", otx_pulses),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            payload = _load(_snapshot_text() or "")
            problem = schema_drift(payload or {})
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        url = _indicator_url("IPv4", "1.1.1.1", "general")
        payload, _cache, warning = _fetch(url, None, ttl=60, force_live=True)
        if warning:
            return Probe(self.key, False, warning)
        problem = schema_drift(payload or {})
        if problem:
            return Probe(self.key, False, problem)
        record = _indicator_record(payload or {}, "IPv4", "1.1.1.1", "general")
        if record["value"] != "1.1.1.1":
            return Probe(self.key, False, "live probe returned a different indicator")
        problem = _response_problem("otx_indicator", record)
        if problem:
            return Probe(self.key, False, problem)
        pulses, _cache, warning = _fetch(
            PULSES_URL,
            {"limit": "1", "page": "1"},
            ttl=60,
            force_live=True,
        )
        if warning:
            return Probe(self.key, False, warning)
        problem = _pulses_drift(pulses or {})
        if problem:
            return Probe(self.key, False, problem)
        results = (pulses or {}).get("results") or []
        if results:
            row = _pulse(results[0])
            if row is None:
                return Probe(self.key, False, "OTX schema drift, missing id")
            problem = _response_problem("otx_pulses", row)
            if problem:
                return Probe(self.key, False, problem)
        return Probe(self.key, True, "live ok")


def schema_drift(payload: dict) -> str | None:
    if not isinstance(payload, dict):
        return "OTX payload was not an object"
    if isinstance(payload.get("indicator"), str) and isinstance(payload.get("type"), str):
        return None
    if "indicator" in payload or "type" in payload:
        return "OTX schema drift, missing indicator"
    if "results" in payload:
        return _pulses_drift(payload)
    return "OTX schema drift, missing indicator"


def _same_indicator(kind: str, found, value: str) -> bool:
    if not isinstance(found, str):
        return False
    if found == value:
        return True
    if kind == "IPv6":
        try:
            return ipaddress.IPv6Address(found) == ipaddress.IPv6Address(value)
        except ValueError:
            return False
    if kind in {"domain", "hostname", "file"}:
        return found.casefold().rstrip(".") == value.casefold().rstrip(".")
    return False


def _indicator_url(kind: str, value: str, section: str) -> str:
    return (
        f"{API_ROOT}/indicators/{quote(kind, safe='')}/"
        f"{quote(value, safe='')}/{quote(section, safe='')}"
    )


def _pulse_params(modified_since: str | None, limit: int, page: str = "1") -> dict[str, str]:
    params = {"limit": str(limit), "page": page}
    if modified_since:
        params = {
            "modified_since": _sydney_param(modified_since),
            "limit": str(limit),
            "page": page,
        }
    return params


def _validate_indicator(kind: str, value: str, section: str) -> str:
    if kind not in _TYPES:
        return "type is not a known OTX indicator type"
    if not isinstance(value, str) or not value.strip():
        return "value is required"
    if len(value) > 2048 or any(ch.isspace() or ord(ch) < 32 for ch in value):
        return "value is not a usable indicator"
    if not isinstance(section, str) or _SECTION.fullmatch(section) is None:
        return "section is not a known OTX section name"
    if kind == "IPv4":
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            return "value is not an IPv4 address"
    elif kind == "IPv6":
        try:
            ipaddress.IPv6Address(value)
        except ValueError:
            return "value is not an IPv6 address"
    elif kind in {"domain", "hostname"} and _DOMAIN.fullmatch(value) is None:
        return "value is not a domain name"
    elif kind == "url":
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username:
            return "value is not an http or https URL"
    elif kind == "file" and _HASH.fullmatch(value) is None:
        return "value is not an MD5, SHA-1 or SHA-256 hash"
    return ""


def _validate_pulses(modified_since: str | None, limit: int) -> str:
    if modified_since:
        if not isinstance(modified_since, str) or _DATE.fullmatch(modified_since) is None:
            return "modified_since must be YYYY-MM-DD"
        try:
            _sydney_param(modified_since)
        except (ValueError, OverflowError):
            return "modified_since must be YYYY-MM-DD"
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        return "limit must be between 1 and 100"
    return ""


def _indicator_problem(section: str, payload: dict) -> str | None:
    if section == "general":
        return schema_drift(payload)
    if not isinstance(payload, dict) or not payload:
        return "OTX payload was not usable"
    markers = _SECTION_MARKERS.get(section)
    if markers is None:
        return None
    if not any(key in payload for key in markers):
        return f"OTX schema drift, missing {markers[0]}"
    return None


def _pulses_drift(payload: dict) -> str | None:
    if not isinstance(payload, dict):
        return "OTX payload was not an object"
    rows = payload.get("results")
    if not isinstance(rows, list):
        return "OTX schema drift, missing results"
    for row in rows:
        if not isinstance(row, dict) or "id" not in row:
            return "OTX schema drift, missing id"
    return None


def _gather_pulses(
    payload: dict,
    cache: str,
    modified_since: str | None,
    limit: int,
) -> tuple[list[dict], str]:
    rows: list[dict] = []
    seen_ids: set[str] = set()
    seen_urls: set[str] = set()
    current: dict | None = payload
    state = cache
    warning = ""
    for _page in range(_MAX_PAGES):
        if current is None or len(rows) >= limit:
            break
        problem = _pulses_drift(current)
        if problem:
            return rows, problem
        for item in current["results"]:
            row = _pulse(item)
            if row is None or row["id"] in seen_ids:
                continue
            if modified_since and not _kept(row["modified"], modified_since):
                continue
            seen_ids.add(row["id"])
            rows.append(row)
            if len(rows) >= limit:
                break
        nxt = current.get("next")
        if not isinstance(nxt, str) or not nxt or len(rows) >= limit:
            break
        if state == "snapshot" or os.environ.get("CYBERAU_OFFLINE") == "1":
            break
        nxt = _absolute_next(nxt)
        if nxt in seen_urls or not _allowed_page(nxt):
            if not _allowed_page(nxt):
                warning = "OTX next page was refused because the host is not allowlisted"
            break
        seen_urls.add(nxt)
        current, state, warning = _fetch(nxt, None, ttl=PULSE_TTL)
        if warning:
            break
        if current is None:
            warning = "OTX payload was not usable"
            break
    return rows[:limit], warning


def _fetch(
    url: str,
    params: dict | None,
    *,
    ttl: int,
    force_live: bool = False,
) -> tuple[dict | None, str, str]:
    snapshot = os.environ.get("CYBERAU_OTX_SNAPSHOT")
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    if snapshot and not force_live:
        text = _read_text(Path(snapshot))
        if text is None:
            return None, "snapshot", "OTX is unavailable offline"
        return _load(text), "snapshot", ""
    data_dir = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-otx"))
    cache = HttpCache(data_dir / "http_cache.sqlite")
    secret = lookup("OTX_API_KEY")
    scope = _auth_scope(secret)
    cache_key = cache.key("GET", url, params, b"", scope)
    cached = cache.get(cache_key)
    if cached and not force_live and (offline or cache.fresh(cached)):
        state = "hit" if cache.fresh(cached) else "stale"
        return _load(cached.body.decode("utf-8")), state, ""
    if offline:
        packaged = _packaged_snapshot(url)
        text = _read_text(packaged)
        if text is None:
            return None, "snapshot", "OTX is unavailable offline"
        return _load(text), "snapshot", ""
    if not secret:
        return None, "snapshot", "OTX_API_KEY is not set"
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    client = HttpClient(
        "otx",
        policy=EgressPolicy(allowlist, "otx"),
        cache=cache,
        limiter=RateLimiter(data_dir / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=1,
        burst=1,
        window="rolling",
        timeout=30,
        retries=1,
        auth_scope=scope,
        transport=_TRANSPORT,
    )
    try:
        try:
            response = client.get(
                url, params=params, headers=_headers(secret), ttl=ttl, skip_cache=force_live
            )
        except (HttpError, EgressDenied, TimeoutError, RateLimited) as exc:
            if force_live:
                return None, "snapshot", _safe(exc, secret)
            stale = cache.get(cache_key)
            if stale:
                return _load(stale.body.decode("utf-8")), "stale", ""
            return None, "snapshot", _safe(exc, secret)
    finally:
        client.close()
    if response.status in (401, 403):
        return None, "snapshot", f"OTX returned {response.status}. Check OTX_API_KEY."
    if response.status == 429:
        stale = None if force_live else cache.get(cache_key)
        if stale:
            return _load(stale.body.decode("utf-8")), "stale", ""
        return None, "snapshot", "OTX returned 429 after backing off"
    if response.status >= 400:
        return None, "snapshot", f"OTX returned {response.status}"
    try:
        text = response.body.decode("utf-8")
    except UnicodeDecodeError:
        return None, response.cache, "OTX payload was not usable"
    return _load(text), response.cache, ""


def _headers(secret: str) -> dict[str, str]:
    return {"X-OTX-API-KEY": secret}


def _auth_scope(secret: str | None) -> str:
    if not secret:
        return "anonymous"
    digest = hashlib.sha256(secret.encode()).hexdigest()[:16]
    return f"otx:{digest}"


def _safe(exc: BaseException, secret: str | None) -> str:
    message = redact(str(exc))
    if secret and len(secret) >= 8 and secret in message:
        message = message.replace(secret, "[REDACTED]")
    return message or "OTX is unavailable"


def _indicator_record(payload: dict, kind: str, value: str, section: str) -> dict:
    info = payload.get("pulse_info") if isinstance(payload.get("pulse_info"), dict) else {}
    pulses = []
    for item in info.get("pulses") or []:
        brief = _pulse_brief(item)
        if brief is not None:
            pulses.append(brief)
    count = info.get("count") if isinstance(info, dict) else None
    if isinstance(count, bool) or not isinstance(count, int):
        count = len(pulses) if pulses else None
    found = payload.get("indicator")
    reported = payload.get("type")
    record: dict = {
        "type": reported if isinstance(reported, str) else kind,
        "value": found if isinstance(found, str) else value,
        "section": section,
        "pulse_count": count,
        "pulses": pulses,
    }
    reputation = _reputation(payload.get("reputation"))
    if reputation is not None:
        record["reputation"] = reputation
    for source_key, target in (
        ("country_code", "country_code"),
        ("country_name", "country_name"),
        ("asn", "asn"),
    ):
        item = payload.get(source_key)
        if isinstance(item, str) and item:
            record[target] = item
    if isinstance(payload.get("data"), list) and section == "malware":
        record["malware"] = _malware(payload["data"])
    if isinstance(payload.get("passive_dns"), list):
        record["passive_dns"] = _passive(payload["passive_dns"])
    if isinstance(payload.get("url_list"), list):
        record["urls"] = _urls(payload["url_list"])
    return record


def _pulse_brief(item: dict) -> dict | None:
    if not isinstance(item, dict) or "id" not in item:
        return None
    return {
        "id": str(item["id"]),
        "name": _text(item.get("name")),
        "description": _text(item.get("description")),
        "modified": str(item.get("modified") or ""),
    }


def _pulse(item: dict) -> dict | None:
    if not isinstance(item, dict) or "id" not in item:
        return None
    tlp = item.get("tlp") or item.get("TLP") or ""
    tlp = tlp.strip().lower() if isinstance(tlp, str) else ""
    if tlp not in _TLP:
        tlp = ""
    return {
        "id": str(item["id"]),
        "name": _text(item.get("name")),
        "description": _text(item.get("description")),
        "author": _author(item),
        "modified": str(item.get("modified") or ""),
        "created": str(item.get("created") or ""),
        "tlp": tlp,
        "tags": _tags(item.get("tags")),
        "references": _refs(item.get("references")),
        "adversary": _text(item.get("adversary")),
        "indicators": _indicators(item.get("indicators")),
    }


def _author(item: dict) -> str:
    name = item.get("author_name")
    if isinstance(name, str) and name.strip():
        return untrusted_text(name, "otx")
    author = item.get("author")
    if isinstance(author, str) and author.strip():
        return untrusted_text(author, "otx")
    if isinstance(author, dict):
        username = author.get("username") or author.get("name") or ""
        if isinstance(username, str) and username.strip():
            return untrusted_text(username, "otx")
    return ""


def _text(value) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""
    return untrusted_text(value, "otx")


def _tags(items) -> list[str]:
    tags = []
    if not isinstance(items, list):
        return tags
    for item in items:
        if not isinstance(item, str):
            continue
        cleaned = re.sub(r"\s+", " ", item).strip()
        if cleaned and len(cleaned) <= 64:
            tags.append(untrusted_text(cleaned, "otx"))
        if len(tags) >= 20:
            break
    return tags


def _refs(items) -> list[str]:
    refs = []
    if not isinstance(items, list):
        return refs
    for item in items:
        if not isinstance(item, str):
            continue
        parts = urlsplit(item)
        if parts.scheme in {"http", "https"} and parts.hostname and not parts.username:
            refs.append(item)
        if len(refs) >= 20:
            break
    return refs


def _indicators(items) -> list[dict]:
    rows = []
    if not isinstance(items, list):
        return rows
    for item in items:
        if not isinstance(item, dict):
            continue
        value = item.get("indicator")
        if not isinstance(value, str) or not value:
            continue
        rows.append(
            {
                "type": str(item.get("type") or ""),
                "value": value,
                "title": _text(item.get("title")),
                "description": _text(item.get("description")),
            }
        )
        if len(rows) >= 50:
            break
    return rows


def _reputation(value):
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, dict):
        score = value.get("threat_score", value.get("reputation"))
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            return score
    return None


def _malware(items: list) -> list[dict]:
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        digest = item.get("hash")
        if not isinstance(digest, str) or not digest:
            continue
        rows.append({"hash": digest, "date": str(item.get("date") or "")})
        if len(rows) >= 50:
            break
    return rows


def _passive(items: list) -> list[dict]:
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        hostname = item.get("hostname") if isinstance(item.get("hostname"), str) else ""
        address = item.get("address") if isinstance(item.get("address"), str) else ""
        if not hostname and not address:
            continue
        rows.append(
            {
                "hostname": hostname,
                "address": address,
                "first": str(item.get("first") or ""),
                "last": str(item.get("last") or ""),
            }
        )
        if len(rows) >= 50:
            break
    return rows


def _urls(items: list) -> list[dict]:
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            continue
        domain = item.get("domain") if isinstance(item.get("domain"), str) else ""
        rows.append({"url": url, "domain": domain, "date": str(item.get("date") or "")})
        if len(rows) >= 50:
            break
    return rows


def _indicator_observation(record: dict) -> dict:
    return {
        "kind": "indicator",
        "type": record["type"],
        "value": record["value"],
        "section": record["section"],
        "pulse_count": record["pulse_count"],
        "pulse_ids": [item["id"] for item in record["pulses"]],
    }


def _pulse_observation(row: dict) -> dict:
    return {
        "kind": "pulse",
        "id": row["id"],
        "modified": row["modified"],
        "indicator_count": len(row["indicators"]),
    }


def _persist(rows: list[dict]) -> None:
    if not rows:
        return
    directory = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-otx"))
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "otx-observations.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _kept(modified: str, day: str) -> bool:
    parsed = _parse_time(modified)
    if parsed is None:
        return False
    start = datetime.fromisoformat(day).replace(tzinfo=_SYDNEY)
    return parsed >= start


def _parse_time(value: str) -> datetime | None:
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
        parsed = parsed.replace(tzinfo=_UTC)
    return parsed


def _sydney_param(day: str) -> str:
    """Start of that civil day in Australia/Sydney, as UTC YYYY-MM-DDTHH:MM:SS."""
    start = datetime.fromisoformat(day).replace(tzinfo=_SYDNEY)
    return start.astimezone(_UTC).strftime("%Y-%m-%dT%H:%M:%S")


def _absolute_next(url: str) -> str:
    if url.startswith(("https://", "http://")):
        return url
    if url.startswith("/"):
        return f"https://{HOST}{url}"
    return url


def _allowed_page(url: str) -> bool:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    return parts.scheme == "https" and host == HOST


def _latest(values: list[str]) -> str | None:
    chosen = [item for item in values if item]
    if not chosen:
        return None
    return max(chosen)


def _response_problem(name: str, record: dict) -> str | None:
    schema = json.loads((_PACKAGE / "schema" / f"{name}.response.json").read_text(encoding="utf-8"))
    try:
        jsonschema.validate(record, schema)
    except jsonschema.ValidationError as exc:
        return "OTX response schema: " + exc.message
    return None


def _snapshot_text() -> str | None:
    snapshot = os.environ.get("CYBERAU_OTX_SNAPSHOT")
    path = Path(snapshot) if snapshot else _PACKAGE / "data" / "indicator_ipv4_general.json"
    return _read_text(path)


def _packaged_snapshot(url: str) -> Path:
    if "/pulses/" in url:
        return _PACKAGE / "data" / "pulses_subscribed_page1.json"
    return _PACKAGE / "data" / "indicator_ipv4_general.json"


def _read_text(path: Path) -> str | None:
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def _load(text: str) -> dict | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _envelope(
    data,
    cache: str,
    urls: list[str] | None = None,
    data_as_of: str | None = None,
    warnings: tuple[str, ...] = (),
) -> dict:
    return envelope(
        "otx",
        data,
        urls=urls or [API_ROOT],
        cache=cache,
        data_as_of=data_as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("otx", connector)
