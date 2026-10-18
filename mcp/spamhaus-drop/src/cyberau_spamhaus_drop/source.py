"""Read-only Spamhaus DROP, DROPv6 and ASN-DROP lists."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from pathlib import Path

import jsonschema
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient
from cyberau_common.ratelimit import RateLimited, RateLimiter
from cyberau_common.secrets import redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector

DROP_V4 = "https://www.spamhaus.org/drop/drop_v4.json"
DROP_V6 = "https://www.spamhaus.org/drop/drop_v6.json"
ASN_DROP = "https://www.spamhaus.org/drop/asndrop.json"
LISTS = (
    ("drop_v4", DROP_V4),
    ("drop_v6", DROP_V6),
    ("asn_drop", ASN_DROP),
)
_FILES = {
    "drop_v4": "drop_v4.json",
    "drop_v6": "drop_v6.json",
    "asn_drop": "asndrop.json",
}
_SBL_ID = re.compile(r"SBL\d{1,12}")
_COUNTRY = re.compile(r"[A-Za-z]{2}")
_NET_FIELDS = ("cidr", "sblid", "rir")
_ASN_FIELDS = ("asn", "rir")
ATTRIBUTION = (
    "Spamhaus DROP, DROPv6 and ASN-DROP. Provided free of charge by Spamhaus. Attribute Spamhaus."
)
_LIMITED = "A second DROP fetch inside an hour was refused by the limiter."
_UNAVAILABLE = "DROP lists are unavailable"
_CACHE_TTL = 24 * 3600
_STALE_IF_ERROR = 24 * 3600
# One refresh is three list downloads, plus retries. The hourly guard below is
# what keeps automatic refreshes to one an hour.
_HTTP_BURST = 15
_HTTP_RATE = _HTTP_BURST / 3600
_PACKAGE = Path(__file__).resolve().parents[2]
_TRANSPORT = None
_SLEEP = time.sleep
_RESOLVER = None


def drop_check_ip(ip: str) -> dict:
    address, problem = _address(ip)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    bundle = _load()
    family = "drop_v4" if isinstance(address, IPv4Address) else "drop_v6"
    if family not in bundle.loaded:
        warnings = bundle.warnings or [_UNAVAILABLE]
        return _envelope([], bundle.cache, bundle.as_of, warnings)
    tree = bundle.v4 if family == "drop_v4" else bundle.v6
    found = tree.find(address)
    rows = [] if found is None else [found]
    return _envelope(rows, bundle.cache, bundle.as_of, bundle.warnings)


def drop_check_asn(asn: int) -> dict:
    number = _asn_number(asn)
    if number is None:
        return _envelope([], "snapshot", warnings=("asn must be an integer >= 1",))
    bundle = _load()
    if "asn_drop" not in bundle.loaded:
        warnings = bundle.warnings or [_UNAVAILABLE]
        return _envelope([], bundle.cache, bundle.as_of, warnings)
    found = bundle.asns.get(number)
    rows = [] if found is None else [found]
    return _envelope(rows, bundle.cache, bundle.as_of, bundle.warnings)


def drop_list_status() -> dict:
    bundle = _load()
    rows = [
        {
            "list": name,
            "entries": bundle.counts.get(name, 0),
            "fetched_at": bundle.times.get(name),
        }
        for name, _url in LISTS
    ]
    return _envelope(rows, bundle.cache, bundle.as_of, bundle.warnings)


def connector() -> Connector:
    return _DropConnector()


class _DropConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="spamhaus-drop",
            server_name="drop",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "drop_check_ip",
                    "Whether an IP is inside a DROP netblock, with SBL id.",
                    drop_check_ip,
                ),
                ToolSpec(
                    "drop_check_asn",
                    "Whether an ASN is on ASN-DROP.",
                    drop_check_asn,
                ),
                ToolSpec(
                    "drop_list_status",
                    "Last fetch time and entry counts.",
                    drop_list_status,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            problem = _snapshot_problem()
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        try:
            _allow_refresh()
            probed = _live_probe()
        except RateLimited:
            return Probe(self.key, False, _LIMITED)
        except Exception as exc:
            return Probe(self.key, False, _failure(exc))
        for name, text, warning in probed:
            if warning:
                return Probe(self.key, False, f"{name}: {warning}")
            problem = schema_drift(text or "", name)
            if problem:
                return Probe(self.key, False, f"{name}: {problem}")
            rows, parse_problem = _parse_lines(text or "")
            record = _probe_record(name, rows or [])
            if parse_problem or record is None:
                reason = parse_problem or "live probe returned no DROP entries"
                return Probe(self.key, False, f"{name}: {reason}")
            tool = "drop_check_asn" if name == "asn_drop" else "drop_check_ip"
            try:
                jsonschema.validate(record, _response_schema(tool))
            except jsonschema.ValidationError as exc:
                return Probe(self.key, False, f"{name}: {exc.message}")
        return Probe(self.key, True, "live ok")


def schema_drift(text: str, kind: str = "drop_v4") -> str | None:
    rows, problem = _parse_lines(text)
    if problem:
        return problem
    return _drift_rows(rows or [], kind)


@dataclass
class _Bundle:
    v4: _PrefixTree
    v6: _PrefixTree
    asns: dict[int, dict]
    counts: dict[str, int]
    times: dict[str, str | None]
    loaded: set[str]
    cache: str
    warnings: list[str] = field(default_factory=list)

    @property
    def as_of(self) -> str | None:
        stamps = [stamp for stamp in self.times.values() if stamp]
        return max(stamps) if stamps else None

    @classmethod
    def empty(cls, cache: str, warnings: list[str]) -> _Bundle:
        return cls(
            v4=_PrefixTree(),
            v6=_PrefixTree(),
            asns={},
            counts={name: 0 for name, _url in LISTS},
            times={name: None for name, _url in LISTS},
            loaded=set(),
            cache=cache,
            warnings=list(warnings),
        )


class _PrefixTree:
    """Longest-prefix match over IPv4 or IPv6 netblocks."""

    def __init__(self) -> None:
        self._root: dict = {}

    def add(self, network, record: dict) -> None:
        node = self._root
        raw = int(network.network_address)
        width = network.max_prefixlen
        for bit in range(network.prefixlen):
            child = (raw >> (width - 1 - bit)) & 1
            node = node.setdefault(child, {})
        node["value"] = record

    def find(self, address) -> dict | None:
        node = self._root
        raw = int(address)
        width = address.max_prefixlen
        found = node.get("value")
        for bit in range(width):
            child = (raw >> (width - 1 - bit)) & 1
            nxt = node.get(child)
            if nxt is None:
                break
            node = nxt
            if "value" in node:
                found = node["value"]
        return found


def _load(*, force_live: bool = False) -> _Bundle:
    if not force_live and os.environ.get("CYBERAU_DROP_SNAPSHOT"):
        return _from_dir(Path(os.environ["CYBERAU_DROP_SNAPSHOT"]), "snapshot")
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    cache = HttpCache(_data_dir() / "http_cache.sqlite")
    if offline:
        cached = _from_http_cache(cache, allow_stale=True)
        if cached is not None:
            return cached
        return _from_dir(_PACKAGE / "data", "snapshot")
    if not force_live and not _needs_network(cache):
        cached = _from_http_cache(cache, allow_stale=False)
        if cached is not None:
            return cached
    try:
        _allow_refresh()
    except RateLimited:
        return _fallback(cache, _LIMITED)
    try:
        return _from_network(cache, force_live=force_live)
    except RateLimited:
        return _fallback(cache, _LIMITED)
    except Exception as exc:
        return _fallback(cache, _failure(exc))


def _from_network(cache: HttpCache, *, force_live: bool) -> _Bundle:
    client = _client(cache)
    fetched: dict[str, tuple[str | None, str | None]] = {}
    warnings: list[str] = []
    states: list[str] = []
    try:
        for name, url in LISTS:
            text, state, warning, when = _get(client, url, force_live=force_live)
            if warning:
                warnings.append(warning)
            fetched[name] = (text, when)
            states.append(state)
    finally:
        client.close()
    return _build(fetched, _merge_cache(states), warnings)


def _get(client: HttpClient, url: str, *, force_live: bool):
    try:
        response = client.get(
            url,
            ttl=_CACHE_TTL,
            stale_if_error=_STALE_IF_ERROR,
            skip_cache=force_live,
        )
    except RateLimited:
        raise
    except Exception as exc:
        return None, "snapshot", _failure(exc), None
    if response.status in (401, 403):
        return None, "snapshot", _denied(response.status), None
    if response.status == 429:
        return None, "snapshot", _TOO_MANY, None
    if response.status >= 400:
        return None, "snapshot", f"upstream status {response.status}", None
    try:
        text = response.body.decode("utf-8")
    except UnicodeDecodeError:
        return None, response.cache, "DROP payload was not UTF-8", None
    when = _now()
    if response.cache in {"hit", "stale"}:
        item = client.cache.get(_cache_key(client.cache, url))
        if item is not None:
            when = _iso(item.fetched_at)
    return text, response.cache, "", when


def _live_probe() -> list[tuple[str, str | None, str]]:
    cache = HttpCache(_data_dir() / "http_cache.sqlite")
    client = _client(cache)
    probed = []
    try:
        for name, url in LISTS:
            text, _state, warning, _when = _get(client, url, force_live=True)
            probed.append((name, text, warning))
    finally:
        client.close()
    return probed


def _probe_record(name: str, rows: list[dict]) -> dict | None:
    required = _ASN_FIELDS if name == "asn_drop" else _NET_FIELDS
    for row in rows:
        if any(field_name not in row for field_name in required):
            continue
        if name == "asn_drop":
            number = _asn_number(row.get("asn"))
            return None if number is None else _asn_record(row, number)
        return _net_record(name, row)
    return None


def _from_http_cache(cache: HttpCache, *, allow_stale: bool) -> _Bundle | None:
    fetched: dict[str, tuple[str | None, str | None]] = {}
    states: list[str] = []
    for name, url in LISTS:
        item = cache.get(_cache_key(cache, url))
        if item is None:
            return None
        fresh = cache.fresh(item)
        if not fresh and not allow_stale:
            return None
        if not fresh and not cache.within_stale(item, _STALE_IF_ERROR):
            return None
        try:
            text = item.body.decode("utf-8")
        except UnicodeDecodeError:
            return None
        fetched[name] = (text, _iso(item.fetched_at))
        states.append("hit" if fresh else "stale")
    return _build(fetched, _merge_cache(states), [])


def _from_dir(root: Path, cache: str) -> _Bundle:
    if not root.is_dir():
        return _Bundle.empty("snapshot", [_UNAVAILABLE])
    fetched: dict[str, tuple[str | None, str | None]] = {}
    warnings: list[str] = []
    for name, filename in _FILES.items():
        path = root / filename
        if not path.is_file():
            warnings.append(f"DROP snapshot missing {filename}")
            fetched[name] = (None, None)
            continue
        fetched[name] = (path.read_text(encoding="utf-8"), None)
    bundle = _build(fetched, cache, warnings)
    if not bundle.loaded and not bundle.warnings:
        bundle.warnings.append(_UNAVAILABLE)
    return bundle


def _fallback(cache: HttpCache, warning: str) -> _Bundle:
    cached = _from_http_cache(cache, allow_stale=True)
    if cached is not None:
        cached.cache = "stale"
        cached.warnings.append(warning)
        return cached
    bundle = _from_dir(_PACKAGE / "data", "snapshot")
    bundle.warnings.append(warning)
    if not bundle.loaded:
        bundle.warnings.append(_UNAVAILABLE)
    return bundle


def _build(
    fetched: dict[str, tuple[str | None, str | None]],
    cache: str,
    warnings: list[str],
) -> _Bundle:
    bundle = _Bundle.empty(cache, warnings)
    for name, (text, when) in fetched.items():
        if text is None:
            continue
        rows, problem = _parse_lines(text)
        if problem or rows is None:
            bundle.warnings.append(problem or "DROP payload was not JSON lines")
            continue
        drift = _drift_rows(rows, name)
        if drift:
            bundle.warnings.append(drift)
            continue
        added = _fill(bundle, name, rows)
        bundle.loaded.add(name)
        bundle.counts[name] = len(added)
        if when:
            bundle.times[name] = when
        if added and when:
            _persist(name, added, when, bundle.warnings)
    bundle.warnings = _unique(bundle.warnings)
    return bundle


def _fill(bundle: _Bundle, name: str, rows: list[dict]) -> list[dict]:
    added: list[dict] = []
    required = _ASN_FIELDS if name == "asn_drop" else _NET_FIELDS
    for row in rows:
        if any(field_name not in row for field_name in required):
            continue
        if name == "asn_drop":
            number = _asn_number(row.get("asn"))
            if number is None:
                bundle.warnings.append("DROP entry has an invalid ASN")
                continue
            bundle.asns[number] = _asn_record(row, number)
            added.append(row)
            continue
        try:
            network = ip_network(str(row["cidr"]), strict=False)
        except ValueError:
            bundle.warnings.append("DROP entry has an invalid CIDR")
            continue
        if (network.version == 4) != (name == "drop_v4"):
            bundle.warnings.append("DROP entry has the wrong IP family")
            continue
        tree = bundle.v4 if name == "drop_v4" else bundle.v6
        tree.add(network, _net_record(name, row))
        added.append(row)
    return added


def _parse_lines(text: str) -> tuple[list[dict] | None, str]:
    rows: list[dict] = []
    for line in text.lstrip("\ufeff").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            return None, "DROP payload was not JSON lines"
        if not isinstance(item, dict):
            return None, "DROP payload was not JSON lines"
        rows.append(item)
    return rows, ""


def _drift_rows(rows: list[dict], kind: str) -> str | None:
    if not rows:
        return None
    required = _ASN_FIELDS if kind == "asn_drop" else _NET_FIELDS
    missing = [name for name in required if name not in rows[0]]
    if missing:
        return "DROP schema drift, missing " + ", ".join(missing)
    return None


def _snapshot_problem() -> str | None:
    root = _snapshot_root()
    for name, filename in _FILES.items():
        path = root / filename
        if not path.is_file():
            return f"DROP snapshot missing {filename}"
        problem = schema_drift(path.read_text(encoding="utf-8"), name)
        if problem:
            return problem
    return None


def _persist(kind: str, rows: list[dict], seen_at: str, warnings: list[str]) -> None:
    path = _data_dir() / "drop_history.sqlite"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS drop_entries (
                    list_name TEXT NOT NULL,
                    identity TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    PRIMARY KEY (list_name, identity)
                )
                """
            )
            for row in rows:
                identity = str(row.get("cidr") or row.get("asn"))
                conn.execute(
                    """
                    INSERT INTO drop_entries
                        (list_name, identity, payload, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(list_name, identity) DO UPDATE SET
                        payload=excluded.payload,
                        last_seen=excluded.last_seen
                    """,
                    (kind, identity, json.dumps(row, sort_keys=True), seen_at, seen_at),
                )
    except sqlite3.Error as exc:
        warnings.append(redact(str(exc)))


def _net_record(kind: str, row: dict) -> dict:
    return {
        "list": kind,
        "cidr": _cidr(row["cidr"]),
        "sbl_id": _token(row["sblid"], _SBL_ID),
        "rir": _text(row.get("rir", "")),
    }


def _asn_record(row: dict, number: int) -> dict:
    return {
        "list": "asn_drop",
        "asn": number,
        "rir": _text(row.get("rir", "")),
        "domain": _text(row.get("domain", "")),
        "cc": _token(row.get("cc"), _COUNTRY),
        "asname": _text(row.get("asname", "")),
    }


def _token(value: object, shape: re.Pattern) -> str:
    """Return a short identifier as is when it has the expected shape, else wrapped."""
    raw = "" if value is None else str(value).strip()
    if shape.fullmatch(raw):
        return raw
    return _text(raw)


def _cidr(value: object) -> str:
    try:
        return str(ip_network(str(value), strict=False))
    except ValueError:
        return _text(value)


def _failure(exc: Exception) -> str:
    """Exception text can carry upstream hosts or bodies, so it is wrapped."""
    detail = redact(str(exc)).strip()
    return untrusted_text(detail, "spamhaus-drop") if detail else _UNAVAILABLE


def _text(value: object) -> str:
    if value is None:
        return ""
    raw = str(value).strip()
    if not raw:
        return ""
    return untrusted_text(raw, "spamhaus-drop")


def _address(ip: str):
    if not isinstance(ip, str):
        return None, "ip must be an IPv4 or IPv6 address"
    try:
        address = ip_address(ip.strip())
    except ValueError:
        return None, "ip must be an IPv4 or IPv6 address"
    if isinstance(address, IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address, ""


def _asn_number(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 1:
        return None
    return value


def _needs_network(cache: HttpCache) -> bool:
    for _name, url in LISTS:
        item = cache.get(_cache_key(cache, url))
        if item is None or not cache.fresh(item):
            return True
    return False


def _allow_refresh() -> None:
    RateLimiter(_data_dir() / "rate_limit.sqlite", sleeper=_SLEEP).acquire(
        "spamhaus-drop:refresh",
        rate=1 / 3600,
        burst=1,
        window="rolling",
        timeout=0,
    )


def _client(cache: HttpCache) -> HttpClient:
    kwargs = {}
    if _RESOLVER is not None:
        kwargs["resolver"] = _RESOLVER
    return HttpClient(
        "spamhaus-drop",
        policy=EgressPolicy(_allowlist(), "spamhaus-drop", **kwargs),
        cache=cache,
        limiter=RateLimiter(_data_dir() / "rate_limit.sqlite", sleeper=_SLEEP),
        user_agent=USER_AGENT,
        rate=_HTTP_RATE,
        burst=_HTTP_BURST,
        window="rolling",
        timeout=30,
        retries=3,
        transport=_TRANSPORT,
        sleeper=_SLEEP,
        rng=lambda: 0.0,
    )


def _denied(status: int) -> str:
    return (
        f"Spamhaus refused the request ({status}). "
        "DROP lists do not use an API key, so no credential env var is set."
    )


_TOO_MANY = "Spamhaus rate limited the request (429) after honouring Retry-After."


def _envelope(data, cache: str, data_as_of: str | None = None, warnings=()) -> dict:
    return envelope(
        "spamhaus-drop",
        data,
        urls=[url for _name, url in LISTS],
        cache=cache,
        data_as_of=data_as_of,
        warnings=_unique(list(warnings)),
        attribution=ATTRIBUTION,
    )


def _merge_cache(states: list[str]) -> str:
    if not states:
        return "snapshot"
    if "stale" in states:
        return "stale"
    if "miss" in states:
        return "miss"
    if "hit" in states:
        return "hit"
    return "snapshot"


def _unique(items: list[str]) -> list[str]:
    seen: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.append(item)
    return seen


def _cache_key(cache: HttpCache, url: str) -> str:
    return cache.key("GET", url, None, b"", "anonymous")


def _response_schema(name: str) -> dict:
    path = _PACKAGE / "schema" / f"{name}.response.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _snapshot_root() -> Path:
    override = os.environ.get("CYBERAU_DROP_SNAPSHOT")
    return Path(override) if override else _PACKAGE / "data"


def _data_dir() -> Path:
    return Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-spamhaus-drop"))


def _allowlist() -> Path:
    override = os.environ.get("CYBERAU_EGRESS_ALLOWLIST")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


register_connector("spamhaus-drop", connector)
