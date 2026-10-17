"""Read-only Shodan InternetDB lookups."""

import ipaddress
import json
import os
from pathlib import Path
from typing import Annotated
from urllib.parse import quote

import jsonschema
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from pydantic import Field

ROOT = "https://internetdb.shodan.io"
ATTRIBUTION = (
    "Shodan InternetDB. Free for non-commercial use; commercial use needs an enterprise licence."
)
REQUIRED = ("ip", "ports", "hostnames", "cpes", "tags", "vulns")
_LISTS = ("hostnames", "cpes", "tags", "vulns")
_PACKAGE = Path(__file__).resolve().parents[2]
_TRANSPORT = None
_TTL = 24 * 3600


def internetdb_ip(ip: Annotated[str, Field(description="IPv4 or IPv6 address")]) -> dict:
    address = _parse_ip(ip)
    if address is None:
        return _envelope(None, "snapshot", warnings=("ip must be an IPv4 or IPv6 address",))
    url = _url(address)
    payload, status, cache, warning = _fetch(url)
    if warning:
        return _envelope(None, cache, url, warnings=(warning,))
    if status in (401, 403):
        return _envelope(None, cache, url, warnings=(_denied(status),))
    if status == 429:
        return _envelope(
            None,
            cache,
            url,
            warnings=("InternetDB rate limited the request (429) after honouring Retry-After",),
        )
    if status == 404 or (payload is not None and _is_empty(payload)):
        return _envelope(
            _empty(address),
            cache,
            url,
            warnings=("InternetDB has no information for this address",),
        )
    if payload is None:
        return _envelope(None, cache, url, warnings=("InternetDB payload was not usable",))
    if status >= 400:
        return _envelope(None, cache, url, warnings=(f"InternetDB returned status {status}",))
    drift = schema_drift(payload)
    if drift:
        return _envelope(None, cache, url, warnings=(drift,))
    if str(payload.get("ip")) != address:
        return _envelope(
            _empty(address),
            cache,
            url,
            warnings=("no matching address in the offline snapshot or cache",),
        )
    record = _record(payload)
    _persist(record)
    return _envelope(record, cache, url)


def connector() -> Connector:
    return _InternetDbConnector()


class _InternetDbConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="shodan-internetdb",
            server_name="internetdb",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "internetdb_ip",
                    "Passive exposure summary for an IP.",
                    internetdb_ip,
                )
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            try:
                payload = _load(_snapshot_text())
            except OSError:
                return Probe(self.key, False, "InternetDB snapshot is unavailable")
            if payload is None:
                return Probe(self.key, False, "InternetDB payload was not usable")
            problem = schema_drift(payload)
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        payload, status, _cache, warning = _fetch(_url("1.1.1.1"), force_live=True)
        if warning:
            return Probe(self.key, False, warning)
        if status != 200 or payload is None:
            return Probe(self.key, False, f"live probe status {status}")
        problem = schema_drift(payload)
        if problem:
            return Probe(self.key, False, problem)
        record = _record(payload)
        mismatch = _response_problem(record)
        if mismatch:
            return Probe(self.key, False, mismatch)
        if not record["ports"] and not record["hostnames"]:
            return Probe(self.key, False, "live probe returned no exposure data")
        return Probe(self.key, True, "live ok")


def schema_drift(payload: dict) -> str | None:
    if not isinstance(payload, dict):
        return "InternetDB payload was not an object"
    if _is_empty(payload):
        return None
    missing = [name for name in REQUIRED if name not in payload]
    if missing:
        return "InternetDB schema drift, missing " + ", ".join(missing)
    ports = payload.get("ports")
    if not isinstance(ports, list) or any(not _port(item) for item in ports):
        return "InternetDB schema drift, ports is not a list of integers"
    if not isinstance(payload.get("ip"), str):
        return "InternetDB schema drift, ip is not a string"
    for name in _LISTS:
        if not isinstance(payload.get(name), list):
            return f"InternetDB schema drift, {name} is not a list"
    return None


def _fetch(url: str, *, force_live: bool = False) -> tuple[dict | None, int, str, str]:
    snapshot = os.environ.get("CYBERAU_INTERNETDB_SNAPSHOT")
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    data_dir = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-internetdb"))
    cache = HttpCache(data_dir / "http_cache.sqlite")
    key = cache.key("GET", url, None, b"", "anonymous")
    if snapshot and not force_live:
        path = Path(snapshot)
        if not path.is_file():
            return None, 0, "snapshot", _unavailable()
        payload = _load(path.read_text(encoding="utf-8"))
        if payload is None:
            return None, 0, "snapshot", "InternetDB payload was not usable"
        status = 404 if _is_empty(payload) else 200
        return payload, status, "snapshot", ""
    cached = cache.get(key)
    if cached and not force_live and (offline or cache.fresh(cached)):
        payload = _load(_decode(cached.body))
        state = "hit" if cache.fresh(cached) else "stale"
        if payload is None:
            return None, cached.status, state, "InternetDB payload was not usable"
        return payload, cached.status, state, ""
    if offline:
        shipped = _PACKAGE / "data" / "ip.json"
        if not shipped.is_file():
            return None, 0, "snapshot", _unavailable()
        payload = _load(shipped.read_text(encoding="utf-8"))
        if payload is None:
            return None, 0, "snapshot", "InternetDB payload was not usable"
        return payload, 200, "snapshot", ""
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    client = HttpClient(
        "shodan-internetdb",
        policy=EgressPolicy(allowlist, "shodan-internetdb"),
        cache=cache,
        limiter=RateLimiter(data_dir / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=1,
        burst=1,
        window="rolling",
        timeout=30,
        retries=1,
        transport=_TRANSPORT,
    )
    try:
        response = client.get(url, ttl=_TTL, skip_cache=force_live)
    except (HttpError, EgressDenied, TimeoutError) as exc:
        message = redact(str(exc))
        if force_live:
            return None, 0, "snapshot", message
        cached = cache.get(key)
        if cached:
            payload = _load(_decode(cached.body))
            if payload is not None:
                return payload, cached.status, "stale", ""
        return None, 0, "snapshot", message
    finally:
        client.close()
    payload = _load(_decode(response.body))
    return payload, response.status, response.cache, ""


def _record(payload: dict) -> dict:
    return {
        "ip": str(payload["ip"]),
        "ports": [int(port) for port in payload["ports"]],
        "hostnames": [_text(item) for item in payload["hostnames"]],
        "cpes": [str(item) for item in payload["cpes"]],
        "tags": [_text(item) for item in payload["tags"]],
        "vulns": [str(item) for item in payload["vulns"]],
    }


def _empty(address: str) -> dict:
    return {
        "ip": address,
        "ports": [],
        "hostnames": [],
        "cpes": [],
        "tags": [],
        "vulns": [],
    }


def _text(value) -> str:
    return untrusted_text(str(value), "shodan-internetdb")


def _parse_ip(value: str) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or any(char.isspace() for char in text):
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _url(address: str) -> str:
    return f"{ROOT}/{quote(address, safe=':')}"


def _is_empty(payload: dict) -> bool:
    return "detail" in payload and "ports" not in payload


def _port(item) -> bool:
    return isinstance(item, int) and not isinstance(item, bool)


def _persist(record: dict) -> None:
    kept = ("ports", "hostnames", "cpes", "tags", "vulns")
    if not any(record.get(name) for name in kept):
        return
    directory = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-internetdb"))
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "internetdb-observations.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def _snapshot_text() -> str:
    snapshot = os.environ.get("CYBERAU_INTERNETDB_SNAPSHOT")
    path = Path(snapshot) if snapshot else _PACKAGE / "data" / "ip.json"
    return path.read_text(encoding="utf-8")


def _response_problem(record: dict) -> str | None:
    schema_path = _PACKAGE / "schema" / "internetdb_ip.response.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(record, schema)
    except jsonschema.ValidationError as exc:
        return "InternetDB response schema mismatch: " + exc.message
    return None


def _envelope(data, cache: str, url: str | None = None, warnings: tuple[str, ...] = ()) -> dict:
    return envelope(
        "shodan-internetdb",
        data,
        urls=[] if url is None else [url],
        cache=cache,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _load(text: str) -> dict | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _decode(body: bytes) -> str:
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def _unavailable() -> str:
    return "InternetDB is unavailable offline and no cached or snapshot record exists"


def _denied(status: int) -> str:
    return (
        f"InternetDB refused the request ({status}). "
        "No API key env var applies; this connector does not read one."
    )


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("shodan-internetdb", connector)
