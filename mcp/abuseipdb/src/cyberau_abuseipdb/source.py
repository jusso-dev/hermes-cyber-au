"""Read-only AbuseIPDB IP reputation. Reporting an address is not implemented."""

import ipaddress
import json
import os
import random
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

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

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
BLOCK_URL = "https://api.abuseipdb.com/api/v2/check-block"
ATTRIBUTION = (
    "AbuseIPDB (https://www.abuseipdb.com/). "
    "This product is not endorsed by AbuseIPDB. "
    "Terms were not confirmed at build time; check them before release."
)
_ENV_KEY = "ABUSEIPDB_API_KEY"
_DAY = 86_400
_CHECK_RATE = 900 / _DAY
_BLOCK_RATE = 80 / _DAY
_BURST = 4
_CACHE_TTL = 6 * 3600
_CHECK_FIELDS = ("ipAddress", "abuseConfidenceScore", "totalReports")
_PACKAGE = Path(__file__).resolve().parents[2]
_Ip = Annotated[str, Field(description="IPv4 or IPv6 address")]
_Age = Annotated[int, Field(ge=1, le=365)]
_TRANSPORT = None
_SLEEP = time.sleep
_RNG = random.random


def abuseipdb_check_ip(ip: _Ip, max_age_days: _Age = 90) -> dict:
    parsed = _parse_ip(ip)
    if isinstance(parsed, str):
        return _envelope(None, "snapshot", warnings=(parsed,), urls=(CHECK_URL,))
    problem = _validate_age(max_age_days)
    if problem:
        return _envelope(None, "snapshot", warnings=(problem,), urls=(CHECK_URL,))
    params = {"ipAddress": str(parsed), "maxAgeInDays": str(max_age_days)}
    payload, cache, warning = _fetch(CHECK_URL, params, endpoint="check", rate=_CHECK_RATE)
    if warning:
        return _envelope(None, cache, warnings=(warning,), urls=(CHECK_URL,))
    if payload is None:
        return _envelope(
            None,
            cache,
            warnings=("AbuseIPDB response was not usable",),
            urls=(CHECK_URL,),
        )
    drift = schema_drift(payload)
    if drift:
        return _envelope(None, cache, warnings=(drift,), urls=(CHECK_URL,))
    record = _check_record(payload["data"])
    if record is None:
        return _envelope(
            None,
            cache,
            warnings=("AbuseIPDB response was not usable",),
            urls=(CHECK_URL,),
        )
    if ipaddress.ip_address(record["ip"]) != parsed and cache == "snapshot":
        return _envelope(
            None,
            cache,
            payload,
            warnings=("no matching address in the offline snapshot or cache",),
            urls=(CHECK_URL,),
        )
    _persist(
        [
            _history(
                record["ip"],
                record["abuse_confidence_score"],
                record["total_reports"],
                record["country_code"],
            )
        ]
    )
    return _envelope(record, cache, payload, urls=(CHECK_URL,))


def abuseipdb_check_block(network: str) -> dict:
    parsed = _parse_network(network)
    if isinstance(parsed, str):
        return _envelope(None, "snapshot", warnings=(parsed,), urls=(BLOCK_URL,))
    params = {"network": str(parsed)}
    payload, cache, warning = _fetch(
        BLOCK_URL,
        params,
        endpoint="check-block",
        rate=_BLOCK_RATE,
    )
    if warning:
        return _envelope(None, cache, warnings=(warning,), urls=(BLOCK_URL,))
    if payload is None:
        return _envelope(
            None,
            cache,
            warnings=("AbuseIPDB response was not usable",),
            urls=(BLOCK_URL,),
        )
    drift = schema_drift(payload, kind="check-block")
    if drift:
        return _envelope(None, cache, warnings=(drift,), urls=(BLOCK_URL,))
    record = _block_record(parsed, payload["data"])
    if record is None:
        return _envelope(
            None,
            cache,
            warnings=("AbuseIPDB response was not usable",),
            urls=(BLOCK_URL,),
        )
    if cache == "snapshot" and record["network_address"] != str(parsed.network_address):
        return _envelope(
            _empty_block(parsed),
            cache,
            payload,
            warnings=("no matching network in the offline snapshot or cache",),
            urls=(BLOCK_URL,),
        )
    _persist(
        [
            _history(
                row["ip"],
                row["abuse_confidence_score"],
                row["num_reports"],
                row["country_code"],
            )
            for row in record["reported"]
        ]
    )
    return _envelope(record, cache, payload, urls=(BLOCK_URL,))


def connector() -> Connector:
    return _AbuseIpdbConnector()


class _AbuseIpdbConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="abuseipdb",
            server_name="abuseipdb",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "abuseipdb_check_ip",
                    "Confidence score, report count, ISP, usage type and country.",
                    abuseipdb_check_ip,
                ),
                ToolSpec(
                    "abuseipdb_check_block",
                    "Summary for a CIDR (at most /24 on the free plan).",
                    abuseipdb_check_block,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            try:
                payload = _load(_snapshot_text("check"))
            except OSError as exc:
                return Probe(self.key, False, str(exc))
            problem = schema_drift(payload or {})
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        payload, _cache, warning = _fetch(
            CHECK_URL,
            {"ipAddress": "1.1.1.1", "maxAgeInDays": "1"},
            endpoint="check",
            rate=_CHECK_RATE,
            force_live=True,
        )
        if warning:
            return Probe(self.key, False, warning)
        problem = schema_drift(payload or {})
        if problem:
            return Probe(self.key, False, problem)
        record = None if payload is None else _check_record(payload.get("data") or {})
        if record is None:
            return Probe(self.key, False, "live probe returned no address")
        schema_problem = _response_problem("abuseipdb_check_ip", record)
        if schema_problem:
            return Probe(self.key, False, schema_problem)
        return Probe(self.key, True, "live ok")


def schema_drift(payload: dict, *, kind: str = "check") -> str | None:
    data = payload.get("data")
    if not isinstance(data, dict):
        return "AbuseIPDB payload has no data object"
    if kind == "check-block":
        if "networkAddress" not in data or "reportedAddress" not in data:
            return "AbuseIPDB schema drift, missing networkAddress"
        reported = data.get("reportedAddress")
        if not isinstance(reported, list):
            return "AbuseIPDB schema drift, reportedAddress is not a list"
        if reported and (
            not isinstance(reported[0], dict)
            or "ipAddress" not in reported[0]
            or "abuseConfidenceScore" not in reported[0]
        ):
            return "AbuseIPDB schema drift, missing ipAddress"
        return None
    missing = [name for name in _CHECK_FIELDS if name not in data]
    if missing:
        return "AbuseIPDB schema drift, missing " + ", ".join(missing)
    return None


class _EndpointLimiter:
    """Separate daily budgets for check and check-block on one AbuseIPDB host."""

    def __init__(self, inner: RateLimiter, endpoint: str) -> None:
        self._inner = inner
        self._endpoint = endpoint

    def acquire(
        self,
        key: str,
        *,
        rate: float,
        burst: int,
        window: str = "rolling",
        timeout: float = 60.0,
    ) -> None:
        self._inner.acquire(
            f"abuseipdb:{self._endpoint}",
            rate=rate,
            burst=burst,
            window=window,
            timeout=timeout,
        )


def _fetch(
    url: str,
    params: dict,
    *,
    endpoint: str,
    rate: float,
    force_live: bool = False,
) -> tuple[dict | None, str, str]:
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    snapshot_env = os.environ.get("CYBERAU_ABUSEIPDB_SNAPSHOT")
    data_dir = _data_dir()
    cache = HttpCache(data_dir / "http_cache.sqlite")
    key = cache.key("GET", url, params, b"", "anonymous")
    if not force_live and not snapshot_env:
        cached = cache.get(key)
        if cached and (offline or cache.fresh(cached)):
            state = "hit" if cache.fresh(cached) else "stale"
            return _load(cached.body.decode("utf-8")), state, ""
        if offline:
            return _offline_snapshot(endpoint)
    if not force_live and snapshot_env:
        return _offline_snapshot(endpoint)

    secret = lookup(_ENV_KEY)
    if not secret:
        return None, "snapshot", f"{_ENV_KEY} is not set"
    client = _client(data_dir, cache, endpoint, rate)
    try:
        response = client.get(
            url,
            params=params,
            headers={"Accept": "application/json", "Key": secret},
            ttl=_CACHE_TTL,
            skip_cache=force_live,
        )
    except (HttpError, EgressDenied, TimeoutError, RateLimited) as exc:
        if isinstance(exc, RateLimited):
            return None, "snapshot", "AbuseIPDB local rate limit reached. Retry shortly."
        cached = None if force_live else cache.get(key)
        if cached:
            return _load(cached.body.decode("utf-8")), "stale", ""
        return None, "snapshot", _safe(str(exc), secret)
    finally:
        client.close()
    payload = _load(response.body.decode("utf-8"))
    if response.status >= 400:
        if response.status == 429:
            cached = cache.get(key)
            if cached:
                return _load(cached.body.decode("utf-8")), "stale", ""
        return None, "snapshot", _status_warning(response.status, payload, secret)
    return payload, response.cache, ""


def _offline_snapshot(endpoint: str) -> tuple[dict | None, str, str]:
    try:
        text = _snapshot_text(endpoint)
    except OSError:
        return None, "snapshot", "AbuseIPDB is unavailable offline and no cached check exists"
    return _load(text), "snapshot", ""


def _client(data_dir: Path, cache: HttpCache, endpoint: str, rate: float) -> HttpClient:
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    return HttpClient(
        "abuseipdb",
        policy=EgressPolicy(allowlist, "abuseipdb"),
        cache=cache,
        limiter=_EndpointLimiter(RateLimiter(data_dir / "rate_limit.sqlite"), endpoint),
        user_agent=USER_AGENT,
        rate=rate,
        burst=_BURST,
        window="rolling",
        transport=_TRANSPORT,
        sleeper=_SLEEP,
        rng=_RNG,
    )


def _check_record(data: dict) -> dict | None:
    score = _as_int(data.get("abuseConfidenceScore"))
    reports = _as_int(data.get("totalReports"))
    address = data.get("ipAddress")
    if score is None or reports is None or not isinstance(address, str):
        return None
    distinct = data.get("numDistinctUsers")
    return {
        "ip": address,
        "abuse_confidence_score": score,
        "total_reports": reports,
        "num_distinct_users": distinct if _as_int(distinct) is not None else None,
        "isp": _text(data.get("isp")),
        "usage_type": _text(data.get("usageType")),
        "country_code": _code(data.get("countryCode")),
        "country_name": _text(data.get("countryName")),
        "domain": _text(data.get("domain")),
        "hostnames": [_text(item) for item in data.get("hostnames") or [] if item],
        "is_whitelisted": bool(data.get("isWhitelisted")),
        "is_tor": bool(data.get("isTor")),
        "is_public": bool(data.get("isPublic", True)),
        "last_reported_at": _optional_str(data.get("lastReportedAt")),
    }


def _block_record(network: ipaddress._BaseNetwork, data: dict) -> dict | None:
    reported = []
    for item in data.get("reportedAddress") or []:
        if not isinstance(item, dict):
            return None
        score = _as_int(item.get("abuseConfidenceScore"))
        count = _as_int(item.get("numReports"))
        address = item.get("ipAddress")
        if score is None or count is None or not isinstance(address, str):
            return None
        reported.append(
            {
                "ip": address,
                "abuse_confidence_score": score,
                "num_reports": count,
                "most_recent_report": _optional_str(item.get("mostRecentReport")),
                "country_code": _code(item.get("countryCode")),
            }
        )
    hosts = data.get("numPossibleHosts")
    return {
        "network": str(network),
        "network_address": str(data.get("networkAddress") or network.network_address),
        "netmask": str(data.get("netmask") or ""),
        "min_address": str(data.get("minAddress") or ""),
        "max_address": str(data.get("maxAddress") or ""),
        "num_possible_hosts": hosts if _as_int(hosts) is not None else None,
        "address_space": _text(data.get("addressSpaceDesc")),
        "reported": reported,
    }


def _empty_block(network: ipaddress._BaseNetwork) -> dict:
    return {
        "network": str(network),
        "network_address": str(network.network_address),
        "netmask": "",
        "min_address": "",
        "max_address": "",
        "num_possible_hosts": None,
        "address_space": "",
        "reported": [],
    }


def _history(ip: str, score: int, reports: int, country: str | None) -> dict:
    return {
        "ip": ip,
        "abuse_confidence_score": score,
        "reports": reports,
        "country_code": country,
        "observed_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _persist(rows: list[dict]) -> None:
    if not rows:
        return
    directory = _data_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "abuseipdb-observations.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | str:
    if not isinstance(value, str) or not value.strip():
        return "ip must be an IPv4 or IPv6 address"
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError:
        return "ip must be an IPv4 or IPv6 address"
    if not _routable_ip(parsed):
        return "private and reserved addresses are not looked up"
    return parsed


def _parse_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | str:
    if not isinstance(value, str) or not value.strip():
        return "network must be a CIDR prefix"
    try:
        parsed = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return "network must be a CIDR prefix"
    if parsed.version == 4 and parsed.prefixlen < 24:
        return "network must be at most a /24 on the free plan"
    if parsed.version == 6 and parsed.prefixlen < 64:
        return "IPv6 network must be at most a /64"
    if not _routable_network(parsed):
        return "private and reserved networks are not looked up"
    return parsed


def _routable_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip.is_global
        and not ip.is_multicast
        and not ip.is_reserved
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_unspecified
        and not ip.is_private
    )


def _routable_network(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    if network.network_address.is_multicast:
        return False
    return bool(network.is_global)


def _validate_age(value: int) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 365:
        return "max_age_days must be between 1 and 365"
    return ""


def _status_warning(status: int, payload: dict | None, secret: str) -> str:
    detail = ""
    if isinstance(payload, dict) and isinstance(payload.get("errors"), list) and payload["errors"]:
        first = payload["errors"][0]
        if isinstance(first, dict) and first.get("detail"):
            detail = _text(first.get("detail"))
    if status in (401, 403):
        message = (
            f"AbuseIPDB rejected the API key (HTTP {status}). Set {_ENV_KEY} to a valid key."
        )
    elif status == 429:
        message = "AbuseIPDB daily limit reached (HTTP 429). Retry-After was honoured."
    else:
        message = f"AbuseIPDB returned HTTP {status}"
    if detail:
        message = f"{message} {detail}"
    return _safe(message, secret)


def _response_problem(name: str, record: dict) -> str | None:
    path = _PACKAGE / "schema" / f"{name}.response.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(record, schema)
    except jsonschema.ValidationError as exc:
        return f"AbuseIPDB response schema: {exc.message}"
    return None


def _text(value) -> str:
    if value is None or value == "":
        return ""
    return untrusted_text(str(value), "abuseipdb")


def _code(value) -> str | None:
    if value is None or value == "":
        return None
    return str(value)


def _optional_str(value) -> str | None:
    if value is None or value == "":
        return None
    return str(value)


def _as_int(value) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _safe(message: str, secret: str | None) -> str:
    cleaned = redact(message)
    if secret:
        cleaned = cleaned.replace(secret, "[REDACTED]")
    return cleaned


def _snapshot_text(endpoint: str) -> str:
    override = os.environ.get("CYBERAU_ABUSEIPDB_SNAPSHOT")
    if override:
        return Path(override).read_text(encoding="utf-8")
    name = "check_ip.json" if endpoint == "check" else "check_block.json"
    return (_PACKAGE / "data" / name).read_text(encoding="utf-8")


def _load(text: str) -> dict | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _data_dir() -> Path:
    return Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-abuseipdb"))


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


def _envelope(
    data,
    cache: str,
    payload: dict | None = None,
    warnings: tuple[str, ...] = (),
    urls: tuple[str, ...] = (CHECK_URL,),
) -> dict:
    as_of = None
    if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
        body = payload["data"]
        as_of = body.get("lastReportedAt")
        if not as_of:
            recent = [
                item.get("mostRecentReport")
                for item in body.get("reportedAddress") or []
                if isinstance(item, dict) and item.get("mostRecentReport")
            ]
            as_of = max(recent) if recent else None
    return envelope(
        "abuseipdb",
        data,
        urls=list(urls),
        cache=cache,
        data_as_of=None if as_of is None else str(as_of),
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


register_connector("abuseipdb", connector)
