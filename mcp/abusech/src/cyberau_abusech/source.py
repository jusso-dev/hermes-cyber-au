"""Read-only abuse.ch connector: URLhaus, ThreatFox, MalwareBazaar and Feodo Tracker.

Metadata only. No sample download endpoint is called and no sample is written to disk.
"""

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

import jsonschema
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError, Response
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from cyberau_common.snapshot import unavailable
from pydantic import Field

SOURCE = "abusech"
ENV_KEY = "ABUSECH_AUTH_KEY"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST = "https://urlhaus-api.abuse.ch/v1/host/"
URLHAUS_PAYLOAD = "https://urlhaus-api.abuse.ch/v1/payload/"
URLHAUS_RECENT = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1/"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
BAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
ATTRIBUTION = (
    "Data from abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker). "
    "abuse.ch terms: free for not-for-profit use within query volume limits, commercial "
    "users may need a paid subscription through Spamhaus, and high-volume automated "
    "harvesting is not allowed. Feodo Tracker datasets are CC0. The operator decides "
    "whether the terms allow their use."
)
SNAPSHOT_ENV = "CYBERAU_ABUSECH_SNAPSHOT"
NO_KEY = (
    f"{ENV_KEY} is not set. Get a free Auth-Key at https://auth.abuse.ch/ and add it to "
    "the profile .env"
)
SNAPSHOT_WARNING = (
    f"served from the operator-supplied snapshot file ({SNAPSHOT_ENV}), not a live abuse.ch fetch"
)
_LABELS = {
    "urlhaus": "URLhaus",
    "threatfox": "ThreatFox",
    "malwarebazaar": "MalwareBazaar",
    "feodo": "Feodo Tracker",
}

LOOKUP_TTL = 3600
RECENT_TTL = 900
FEODO_TTL = 3600

_PACKAGE = Path(__file__).resolve().parents[2]
_TRANSPORT = None
_SLEEP = time.sleep
_CLOCK = time.monotonic
_RESOLVER = None

_Indicator = Annotated[str, Field(min_length=3)]
_IndicatorType = Literal["url", "domain", "ip", "md5", "sha1", "sha256"]
_Days = Annotated[int, Field(ge=1, le=7)]
_Limit = Annotated[int, Field(ge=1, le=1000)]
_Country = Annotated[str, Field(pattern=r"^[A-Z]{2}$")]

_HASH_LENGTH = {"md5": 32, "sha1": 40, "sha256": 64}
_HEX = re.compile(r"^[0-9a-f]+$")
_DOMAIN = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$"
)
_TOKEN = re.compile(r"^[A-Za-z0-9_.:+/=-]{1,200}$")
_COUNTRY = re.compile(r"^[A-Z]{2}$")
_NO_RESULT = {"no_results", "no_result", "hash_not_found"}
_MAX_URLS = 50
_MAX_TAGS = 20
_SECRET_NOTE = "[REDACTED]"


@dataclass(frozen=True)
class _Call:
    platform: str
    url: str
    body: dict | None
    encoding: str
    ttl: int
    snapshot_key: str


@dataclass
class _Outcome:
    payload: object | None = None
    cache: str = "snapshot"
    warning: str = ""
    unkeyed: bool = False


def _down(platform: str, reason: str, *, unkeyed: bool = False) -> _Outcome:
    """No live, cached or operator data for this platform: say so and serve nothing."""
    return _Outcome(warning=unavailable(_LABELS[platform], reason), unkeyed=unkeyed)


def abusech_lookup(indicator: _Indicator, type: _IndicatorType | None = None) -> dict:
    if not isinstance(indicator, str) or len(indicator.strip()) < 3:
        return _envelope(
            {"records": [], "platforms": {}}, "snapshot", [], warnings=("indicator is required",)
        )
    value = _refang(indicator.strip())
    kind = type or _classify(value)
    if kind is None:
        return _envelope(
            {"records": [], "platforms": {}},
            "snapshot",
            [],
            warnings=("could not tell what kind of indicator this is; pass type",),
        )
    problem = _validate(kind, value)
    if problem:
        return _envelope({"records": [], "platforms": {}}, "snapshot", [], warnings=(problem,))
    if kind in _HASH_LENGTH or kind == "domain":
        value = value.lower()
    plan = _lookup_plan(kind, value)
    records: list[dict] = []
    platforms: dict[str, str] = {}
    outcomes: list[_Outcome] = []
    warnings: list[str] = []
    with _Session() as session:
        for call, parse in plan:
            outcome = session.fetch(call)
            outcomes.append(outcome)
            status, found, warning = _read(call, outcome, parse)
            platforms[call.platform] = status
            records.extend(found)
            if warning:
                warnings.append(warning)
    warnings.extend(_remember(records, outcomes))
    data = {"indicator_type": kind, "records": records, "platforms": platforms}
    return _envelope(
        data,
        _merge_cache(outcomes),
        [call.url for call, _parse in plan],
        warnings=_unique(warnings + _cache_notes(outcomes)),
    )


def threatfox_recent(days: _Days = 1, malware: str | None = None, limit: _Limit = 100) -> dict:
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 7:
        return _envelope([], "snapshot", [], warnings=("days must be between 1 and 7",))
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
        return _envelope([], "snapshot", [], warnings=("limit must be between 1 and 1000",))
    if malware is not None and not isinstance(malware, str):
        return _envelope([], "snapshot", [], warnings=("malware must be text",))
    call = _Call(
        "threatfox",
        THREATFOX_API,
        {"query": "get_iocs", "days": days},
        "json",
        RECENT_TTL,
        "threatfox:get_iocs",
    )
    with _Session() as session:
        outcome = session.fetch(call)
    needle = (malware or "").strip().lower()
    status, rows, warning = _read(
        call, outcome, lambda payload: _threatfox_records(payload, needle)
    )
    warnings = [warning] if warning else []
    if status == "no_results":
        warnings.append("no ThreatFox IOCs matched")
    rows = rows[:limit]
    warnings.extend(_remember(rows, [outcome]))
    return _envelope(
        rows,
        _merge_cache([outcome]),
        [THREATFOX_API],
        as_of=_newest(rows, "first_seen"),
        warnings=_unique(warnings + _cache_notes([outcome])),
    )


def feodo_blocklist(country: _Country | None = None) -> dict:
    if country is not None and not (isinstance(country, str) and _COUNTRY.fullmatch(country)):
        return _envelope(
            [], "snapshot", [], warnings=("country must be two capital letters, such as AU",)
        )
    call = _Call("feodo", FEODO_URL, None, "get", FEODO_TTL, "feodo:ipblocklist")
    with _Session() as session:
        outcome = session.fetch(call)
    status, rows, warning = _read(call, outcome, _feodo_records)
    if country:
        rows = [row for row in rows if row.get("country") == country]
    warnings = [warning] if warning else []
    if status == "found" and not rows:
        warnings.append("no Feodo Tracker entries matched")
    warnings.extend(_remember(rows, [outcome]))
    return _envelope(
        rows,
        _merge_cache([outcome]),
        [FEODO_URL],
        as_of=_newest(rows, "last_online") or _newest(rows, "first_seen"),
        warnings=_unique(warnings + _cache_notes([outcome])),
    )


def connector() -> Connector:
    return _AbusechConnector()


class _AbusechConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key=SOURCE,
            server_name=SOURCE,
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "abusech_lookup",
                    "Look up an indicator across URLhaus, ThreatFox and MalwareBazaar.",
                    abusech_lookup,
                ),
                ToolSpec(
                    "threatfox_recent", "ThreatFox IOCs from the last N days.", threatfox_recent
                ),
                ToolSpec(
                    "feodo_blocklist",
                    "Current Feodo Tracker C2 IPs, optionally filtered by country.",
                    feodo_blocklist,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if live:
            return _live_probe(self.key)
        if check_schema:
            problems = _snapshot_drift()
            if problems is None:
                return Probe(self.key, True, "offline ok, no local copy to check")
            if problems:
                return Probe(self.key, False, "; ".join(problems))
            return Probe(self.key, True, "schema ok")
        return Probe(self.key, True, "offline ok")


def schema_drift(platform: str, payload: object) -> str | None:
    """Return a short description of the first way a payload leaves the stored schema."""
    error = jsonschema.exceptions.best_match(
        jsonschema.Draft202012Validator(_schema(platform)).iter_errors(payload)
    )
    if error is None:
        return None
    where = "/".join(str(part) for part in error.absolute_path) or "root"
    return f"{platform} schema drift at {where}: {_short(error.message)}"


class _Session:
    """One tool call's view of the network, cache and operator snapshot file."""

    def __init__(self, *, force_live: bool = False) -> None:
        self.force_live = force_live
        self.offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
        # A trailing newline from the .env file would make httpx reject the header and echo it.
        self.key = (lookup(ENV_KEY) or "").strip() or None
        self.data_dir = _data_dir()
        self._clients: dict[str, HttpClient] = {}

    def __enter__(self) -> "_Session":
        return self

    def __exit__(self, *_exc) -> None:
        for client in self._clients.values():
            client.close()

    def fetch(self, call: _Call) -> _Outcome:
        keyed = call.platform != "feodo"
        if keyed and not self.key and not self.offline:
            return _down(call.platform, NO_KEY, unkeyed=True)
        client = self._client(keyed)
        headers = {"Auth-Key": self.key} if keyed and self.key else None
        try:
            response = self._send(client, call, headers)
        except Exception as exc:
            if self.offline and isinstance(exc, HttpError):
                return _snapshot(call)
            return _down(call.platform, self._clean(f"{call.platform} request failed: {exc}"))
        return self._interpret(call, response)

    def _send(self, client: HttpClient, call: _Call, headers: dict | None) -> Response:
        if call.encoding == "get":
            return client.get(call.url, headers=headers, ttl=call.ttl, skip_cache=self.force_live)
        if call.encoding == "form":
            return client.post_form(
                call.url, call.body or {}, headers=headers, ttl=call.ttl, skip_cache=self.force_live
            )
        return client.post_json(
            call.url, call.body or {}, headers=headers, ttl=call.ttl, skip_cache=self.force_live
        )

    def _interpret(self, call: _Call, response: Response) -> _Outcome:
        name = call.platform
        if response.status in (401, 403):
            return _down(
                name,
                f"{name} rejected the request with status {response.status}. Check that "
                f"{ENV_KEY} holds a valid Auth-Key from https://auth.abuse.ch/",
            )
        if response.status == 429:
            wait = response.headers.get("retry-after")
            hint = f", retry after {wait} seconds" if wait else ""
            return _down(name, f"{name} rate limited the request with status 429{hint}")
        if response.status >= 400:
            return _down(name, f"{name} answered with status {response.status}")
        try:
            payload = json.loads(response.body)
        except ValueError:
            return _down(name, f"{name} returned a payload that is not JSON")
        drift = schema_drift(name, payload)
        if drift:
            return _down(name, drift)
        return _Outcome(payload=payload, cache=response.cache)

    def _client(self, keyed: bool) -> HttpClient:
        scope = "keyed" if keyed else "anonymous"
        if scope not in self._clients:
            self._clients[scope] = HttpClient(
                SOURCE,
                policy=EgressPolicy(
                    _allowlist(),
                    SOURCE,
                    # Offline mode never opens a socket, so skip the DNS lookup too.
                    resolver=_offline_resolver if self.offline else _RESOLVER,
                ),
                cache=HttpCache(self.data_dir / "http_cache.sqlite"),
                limiter=RateLimiter(
                    self.data_dir / "rate_limit.sqlite", clock=_CLOCK, sleeper=_SLEEP
                ),
                user_agent=USER_AGENT,
                rate=1.0,
                burst=1,
                window="rolling",
                timeout=30,
                retries=3,
                auth_scope=scope,
                offline=self.offline,
                transport=_TRANSPORT,
                sleeper=_SLEEP,
            )
        return self._clients[scope]

    def _clean(self, text: str) -> str:
        text = redact(text)
        if not self.key:
            return text
        # httpx quotes bad header values with repr(), so cover the escaped forms too.
        for form in (self.key, repr(self.key)[1:-1], repr(self.key.encode())[2:-1]):
            text = text.replace(form, _SECRET_NOTE)
        return text


def _offline_resolver(_host: str) -> list:
    return [ipaddress.ip_address("93.184.216.34")]


def _snapshot(call: _Call) -> _Outcome:
    """Offline with no cached answer: only an operator-supplied snapshot file may answer."""
    if not os.environ.get(SNAPSHOT_ENV):
        return _down(call.platform, "offline mode found no cached answer")
    payload = _snapshot_payloads().get(call.snapshot_key)
    if payload is None:
        return _down(
            call.platform,
            f"offline mode found no cached answer and the {SNAPSHOT_ENV} file does not "
            "cover this query",
        )
    drift = schema_drift(call.platform, payload)
    if drift:
        return _down(call.platform, drift)
    return _Outcome(payload=payload, cache="snapshot")


def _snapshot_payloads() -> dict:
    """Read the operator-supplied snapshot file. Nothing shipped in the package is read."""
    override = os.environ.get(SNAPSHOT_ENV)
    if not override:
        return {}
    path = Path(override)
    if path.is_dir():
        path = path / "snapshot.json"
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _snapshot_drift() -> list[str] | None:
    """Schema problems in the operator snapshot file, or None when there is none to check."""
    if not os.environ.get(SNAPSHOT_ENV):
        return None
    payloads = _snapshot_payloads()
    if not payloads:
        return [f"the {SNAPSHOT_ENV} file is missing or unreadable"]
    problems = []
    for key, payload in payloads.items():
        drift = schema_drift(key.split(":", 1)[0], payload)
        if drift:
            problems.append(drift)
    return problems


_PROBES = (
    _Call("urlhaus", URLHAUS_RECENT, None, "get", 60, "urlhaus:recent"),
    _Call(
        "threatfox",
        THREATFOX_API,
        {"query": "get_iocs", "days": 1},
        "json",
        60,
        "threatfox:get_iocs",
    ),
    _Call(
        "malwarebazaar",
        BAZAAR_API,
        {"query": "get_recent", "selector": "100"},
        "form",
        60,
        "malwarebazaar:get_recent",
    ),
    _Call("feodo", FEODO_URL, None, "get", 60, "feodo:ipblocklist"),
)


def _live_probe(key: str) -> Probe:
    problems = []
    unkeyed = []
    with _Session(force_live=True) as session:
        for call in _PROBES:
            outcome = session.fetch(call)
            if outcome.payload is None:
                if outcome.unkeyed:
                    unkeyed.append(call.platform)
                else:
                    problems.append(f"{call.platform}: {outcome.warning}")
                continue
            status = _query_status(outcome.payload)
            if status not in {"ok", *_NO_RESULT, None}:
                problems.append(f"{call.platform}: answered query_status {_short(status)}")
    skipped = f"{ENV_KEY} is not set, so {', '.join(unkeyed)} were not probed" if unkeyed else ""
    if problems:
        return Probe(key, False, "; ".join([*problems, *([skipped] if skipped else [])]))
    # A missing licence key is not a broken connector: the keyless feeds answered.
    return Probe(key, True, f"live ok; {skipped}" if skipped else "live ok")


def _read(call: _Call, outcome: _Outcome, parse) -> tuple[str, list[dict], str]:
    """Turn one outcome into (status, records, warning)."""
    if outcome.payload is None:
        return "unavailable", [], outcome.warning
    status = _query_status(outcome.payload)
    if status in _NO_RESULT:
        return "no_results", [], ""
    if status not in {"ok", None}:
        reason = f"{call.platform} answered query_status {_short(status)}"
        return "unavailable", [], unavailable(_LABELS[call.platform], reason)
    rows = parse(outcome.payload)
    return ("found" if rows else "no_results"), rows, ""


def _query_status(payload: object) -> str | None:
    if isinstance(payload, dict):
        value = payload.get("query_status")
        return value if isinstance(value, str) else "unknown"
    return None


def _lookup_plan(kind: str, value: str) -> list[tuple[_Call, object]]:
    def urlhaus(url: str, body: dict, snap: str, parse) -> tuple[_Call, object]:
        return _Call("urlhaus", url, body, "form", LOOKUP_TTL, f"urlhaus:{snap}"), parse

    def threatfox(body: dict, snap: str) -> tuple[_Call, object]:
        call = _Call("threatfox", THREATFOX_API, body, "json", LOOKUP_TTL, f"threatfox:{snap}")
        return call, _threatfox_records

    bazaar = (
        _Call(
            "malwarebazaar",
            BAZAAR_API,
            {"query": "get_info", "hash": value},
            "form",
            LOOKUP_TTL,
            f"malwarebazaar:get_info:{value}",
        ),
        _bazaar_records,
    )
    if kind == "url":
        return [
            urlhaus(URLHAUS_URL, {"url": value}, f"url:{value}", _urlhaus_url_records),
            threatfox({"query": "search_ioc", "search_term": value}, f"search_ioc:{value}"),
        ]
    if kind in {"domain", "ip"}:
        return [
            urlhaus(URLHAUS_HOST, {"host": value}, f"host:{value}", _urlhaus_host_records),
            threatfox({"query": "search_ioc", "search_term": value}, f"search_ioc:{value}"),
        ]
    if kind == "sha1":
        return [bazaar]
    field = "md5_hash" if kind == "md5" else "sha256_hash"
    return [
        urlhaus(URLHAUS_PAYLOAD, {field: value}, f"payload:{value}", _urlhaus_payload_records),
        threatfox({"query": "search_hash", "hash": value}, f"search_hash:{value}"),
        bazaar,
    ]


def _classify(value: str) -> str | None:
    lowered = value.lower()
    for kind, length in _HASH_LENGTH.items():
        if len(lowered) == length and _HEX.fullmatch(lowered):
            return kind
    if re.match(r"(?i)^https?://", value):
        return "url"
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return "ip"
    return "domain" if _DOMAIN.fullmatch(lowered) else None


def _validate(kind: str, value: str) -> str:
    if kind in _HASH_LENGTH:
        lowered = value.lower()
        if len(lowered) != _HASH_LENGTH[kind] or not _HEX.fullmatch(lowered):
            return f"indicator is not a {kind} hash"
    elif kind == "ip":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return "indicator is not an IP address"
    elif kind == "domain":
        if not _DOMAIN.fullmatch(value.lower()):
            return "indicator is not a domain name"
    elif kind == "url":
        try:
            parts = urlsplit(value)
        except ValueError:
            return "indicator is not an http or https URL"
        if (
            parts.scheme.lower() not in {"http", "https"}
            or not parts.netloc
            or len(value) > 2048
            or re.search(r"\s", value)
        ):
            return "indicator is not an http or https URL"
    else:
        return "type is not a known indicator type"
    return ""


def _refang(value: str) -> str:
    text = re.sub(r"(?i)^hxxp", "http", value)
    return text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")


def _urlhaus_url_records(payload: dict) -> list[dict]:
    return [_urlhaus_url(payload)]


def _urlhaus_url(row: dict) -> dict:
    return {
        "platform": "urlhaus",
        "kind": "url",
        "indicator_type": "url",
        "indicator": _text(row.get("url")),
        "status": _token(row.get("url_status")),
        "threat": _token(row.get("threat")),
        "host": _text(row.get("host")),
        "date_added": _iso(row.get("date_added")),
        "last_online": _iso(row.get("last_online")),
        "reporter": _text(row.get("reporter")),
        "tags": _tags(row.get("tags")),
        "reference": _text(row.get("urlhaus_reference")),
        "blacklists": _blacklists(row.get("blacklists")),
        "payloads": [_urlhaus_payload_ref(item) for item in _rows(row.get("payloads"))[:_MAX_URLS]],
    }


def _urlhaus_payload_ref(item: dict) -> dict:
    return {
        "sha256": _hash(item.get("response_sha256"), "sha256"),
        "md5": _hash(item.get("response_md5"), "md5"),
        "file_name": _text(item.get("filename")),
        "file_type": _token(item.get("file_type")),
        "file_size": _int(item.get("response_size")),
        "signature": _token(item.get("signature")),
        "first_seen": _iso(item.get("firstseen")),
    }


def _urlhaus_host_records(payload: dict) -> list[dict]:
    urls = _rows(payload.get("urls"))
    host = str(payload.get("host") or "")
    kind = "ip" if _is_ip(host) else "domain"
    return [
        {
            "platform": "urlhaus",
            "kind": "host",
            "indicator_type": kind,
            "indicator": host if kind == "ip" else _text(host),
            "first_seen": _iso(payload.get("firstseen")),
            "url_count": _int(payload.get("url_count")),
            "blacklists": _blacklists(payload.get("blacklists")),
            "urls": [_urlhaus_url(item) for item in urls[:_MAX_URLS]],
            "urls_truncated": len(urls) > _MAX_URLS,
        }
    ]


def _urlhaus_payload_records(payload: dict) -> list[dict]:
    urls = _rows(payload.get("urls"))
    return [
        {
            "platform": "urlhaus",
            "kind": "payload",
            "indicator_type": "sha256",
            "indicator": _hash(payload.get("sha256_hash"), "sha256"),
            "sha256": _hash(payload.get("sha256_hash"), "sha256"),
            "md5": _hash(payload.get("md5_hash"), "md5"),
            "file_type": _token(payload.get("file_type")),
            "file_size": _int(payload.get("file_size")),
            "signature": _token(payload.get("signature")),
            "first_seen": _iso(payload.get("firstseen")),
            "last_seen": _iso(payload.get("lastseen")),
            "url_count": _int(payload.get("url_count")),
            "urls": [
                {
                    "url": _text(item.get("url")),
                    "status": _token(item.get("url_status")),
                    "file_name": _text(item.get("filename")),
                    "first_seen": _iso(item.get("firstseen")),
                    "last_seen": _iso(item.get("lastseen")),
                    "reference": _text(item.get("urlhaus_reference")),
                }
                for item in urls[:_MAX_URLS]
            ],
            "urls_truncated": len(urls) > _MAX_URLS,
        }
    ]


def _threatfox_records(payload: dict, needle: str = "") -> list[dict]:
    rows = []
    for row in _rows(payload.get("data")):
        if needle and needle not in _malware_names(row):
            continue
        ioc_type = _token(row.get("ioc_type"))
        rows.append(
            {
                "platform": "threatfox",
                "kind": "ioc",
                "id": _token(str(row.get("id"))),
                "indicator_type": ioc_type,
                "indicator": _ioc(row.get("ioc"), ioc_type),
                "threat_type": _token(row.get("threat_type")),
                "threat_type_desc": _text(row.get("threat_type_desc")),
                "malware": _token(row.get("malware")),
                "malware_name": _text(row.get("malware_printable")),
                "malware_alias": _text(row.get("malware_alias")),
                "confidence": _int(row.get("confidence_level")),
                "first_seen": _iso(row.get("first_seen")),
                "last_seen": _iso(row.get("last_seen")),
                "reference": _text(row.get("reference")),
                "reporter": _text(row.get("reporter")),
                "tags": _tags(row.get("tags")),
            }
        )
    return rows


def _bazaar_records(payload: dict) -> list[dict]:
    rows = []
    for row in _rows(payload.get("data")):
        intel = row.get("intelligence") if isinstance(row.get("intelligence"), dict) else {}
        clamav = intel.get("clamav") if isinstance(intel.get("clamav"), list) else []
        rows.append(
            {
                "platform": "malwarebazaar",
                "kind": "sample",
                "indicator_type": "sha256",
                "indicator": _hash(row.get("sha256_hash"), "sha256"),
                "sha256": _hash(row.get("sha256_hash"), "sha256"),
                "sha1": _hash(row.get("sha1_hash"), "sha1"),
                "md5": _hash(row.get("md5_hash"), "md5"),
                "first_seen": _iso(row.get("first_seen")),
                "last_seen": _iso(row.get("last_seen")),
                "file_name": _text(row.get("file_name")),
                "file_size": _int(row.get("file_size")),
                "file_type": _token(row.get("file_type")),
                "mime_type": _token(row.get("file_type_mime")),
                "signature": _token(row.get("signature")),
                "reporter": _text(row.get("reporter")),
                "origin_country": _token(row.get("origin_country")),
                "delivery_method": _token(row.get("delivery_method")),
                "imphash": _token(row.get("imphash")),
                "tlsh": _token(row.get("tlsh")),
                "ssdeep": _token(row.get("ssdeep")),
                "tags": _tags(row.get("tags")),
                "comment": _text(row.get("comment")),
                "yara_rules": [
                    _text(rule.get("rule_name"))
                    for rule in _rows(row.get("yara_rules"))[:_MAX_TAGS]
                ],
                "clamav": [_text(name) for name in clamav[:_MAX_TAGS]],
                "downloads": _int(intel.get("downloads")),
                "uploads": _int(intel.get("uploads")),
            }
        )
    return rows


def _feodo_records(payload: list) -> list[dict]:
    rows = []
    for row in _rows(payload):
        address = str(row.get("ip_address") or "")
        country = row.get("country")
        rows.append(
            {
                "platform": "feodo",
                "kind": "c2",
                "indicator_type": "ip",
                "indicator": address if _is_ip(address) else _text(address),
                "port": _int(row.get("port")),
                "status": _token(row.get("status")),
                "hostname": _text(row.get("hostname")),
                "as_number": _int(row.get("as_number")),
                "as_name": _text(row.get("as_name")),
                "country": country.upper()
                if isinstance(country, str) and _COUNTRY.fullmatch(country.upper())
                else None,
                "malware": _token(row.get("malware")),
                "first_seen": _iso(row.get("first_seen")),
                "last_online": _iso(row.get("last_online")),
            }
        )
    return rows


def _rows(value: object) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _text(value: object, max_len: int = 500) -> str | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    text = str(value)
    if not text.strip():
        return None
    wrapped = untrusted_text(text, SOURCE, max_len)
    head = len(f"<<untrusted source={SOURCE}>> ")
    tail = len(" <<end untrusted>>")
    # Break up any marker inside the text so it cannot close the wrapper early.
    inner = re.sub(r">(?=>)", "> ", re.sub(r"<(?=<)", "< ", wrapped[head:-tail]))
    return f"{wrapped[:head]}{inner}{wrapped[-tail:]}"


def _token(value: object) -> str | None:
    if value is None or isinstance(value, (dict, list, bool)):
        return None
    text = str(value)
    if _TOKEN.fullmatch(text):
        return text
    return _text(text, 200)


def _tags(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [tag for tag in (_text(item, 100) for item in value[:_MAX_TAGS]) if tag]


def _hash(value: object, kind: str) -> str | None:
    if not isinstance(value, str):
        return None
    lowered = value.strip().lower()
    if len(lowered) == _HASH_LENGTH[kind] and _HEX.fullmatch(lowered):
        return lowered
    return _text(value, 200)


def _ioc(value: object, ioc_type: str | None) -> str | None:
    text = "" if value is None else str(value)
    if ioc_type and ioc_type.endswith("_hash"):
        kind = ioc_type.removesuffix("_hash")
        if kind in _HASH_LENGTH:
            return _hash(text, kind)
    if ioc_type == "ip:port" and _is_ip_port(text):
        return text
    return _text(text)


def _int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _iso(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().removesuffix(" UTC").removesuffix("Z").replace("T", " ")[:19]
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            parsed = datetime.strptime(text, pattern)
        except ValueError:
            continue
        return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def _blacklists(value: object) -> dict:
    if not isinstance(value, dict):
        return {}
    return {key: _token(value.get(key)) for key in ("spamhaus_dbl", "surbl") if key in value}


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _is_ip_port(value: str) -> bool:
    host, _sep, port = value.rpartition(":")
    return bool(host) and port.isdigit() and _is_ip(host.strip("[]"))


def _malware_names(row: dict) -> str:
    names = (row.get("malware"), row.get("malware_printable"), row.get("malware_alias"))
    return " ".join(str(name) for name in names if name).lower()


def _newest(rows: list[dict], field: str) -> str | None:
    stamps = [row[field] for row in rows if isinstance(row.get(field), str)]
    return max(stamps) if stamps else None


def _merge_cache(outcomes: list[_Outcome]) -> str:
    states = {item.cache for item in outcomes if item.payload is not None}
    for state in ("snapshot", "stale", "miss", "hit"):
        if state in states:
            return state
    return "snapshot"


def _cache_notes(outcomes: list[_Outcome]) -> list[str]:
    states = {item.cache for item in outcomes if item.payload is not None}
    notes = []
    if "snapshot" in states:
        notes.append(SNAPSHOT_WARNING)
    if "stale" in states:
        notes.append("served from stale cache because a fresh answer was not available")
    return notes


def _unique(items: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(items))


def _short(value: object, limit: int = 120) -> str:
    text = re.sub(r"[^\x20-\x7e]", "?", str(value))
    return text[:limit]


@cache
def _schema(name: str) -> dict:
    path = _PACKAGE / "schema" / f"{name}.response.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _remember(records: list[dict], outcomes: list[_Outcome]) -> list[str]:
    """Keep every live or cached record so rolling feeds and changes stay available."""
    if not records or not any(
        item.payload is not None and item.cache != "snapshot" for item in outcomes
    ):
        return []
    try:
        _store(records)
    except (OSError, sqlite3.Error) as exc:
        return [f"intel store write failed: {_short(exc)}"]
    return []


def _store(records: list[dict]) -> None:
    observed = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    path = _data_dir() / "abusech_intel.sqlite"
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path, timeout=5)) as conn, conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS observations (
                key TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                digest TEXT NOT NULL,
                record TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS observations_key ON observations (key)")
        for record in records:
            body = json.dumps(record, sort_keys=True)
            digest = hashlib.sha256(body.encode()).hexdigest()
            key = _record_key(record)
            latest = conn.execute(
                "SELECT digest FROM observations WHERE key = ? ORDER BY rowid DESC LIMIT 1",
                (key,),
            ).fetchone()
            if latest is None or latest[0] != digest:
                conn.execute(
                    "INSERT INTO observations (key, observed_at, digest, record)"
                    " VALUES (?, ?, ?, ?)",
                    (key, observed, digest, body),
                )


def _record_key(record: dict) -> str:
    ident = record.get("id") or record.get("sha256") or record.get("indicator")
    port = record.get("port")
    suffix = f":{port}" if port is not None else ""
    return f"{record['platform']}:{record['kind']}:{ident}{suffix}"


def _envelope(
    data,
    cache: str,
    urls: list[str],
    *,
    as_of: str | None = None,
    warnings: tuple[str, ...] | list[str] = (),
) -> dict:
    return envelope(
        SOURCE,
        data,
        urls=urls,
        cache=cache,
        data_as_of=as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _data_dir() -> Path:
    return Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-abusech"))


def _allowlist() -> Path:
    override = os.environ.get("CYBERAU_EGRESS_ALLOWLIST")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector(SOURCE, connector)
