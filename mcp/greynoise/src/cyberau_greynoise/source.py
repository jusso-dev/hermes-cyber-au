"""Read-only GreyNoise Community IP classification."""

import ipaddress
import json
import os
import re
import time
from pathlib import Path

import jsonschema
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from cyberau_common.snapshot import unavailable

COMMUNITY_API = "https://api.greynoise.io/v3/community"
ATTRIBUTION = "GreyNoise Community. Cite GreyNoise."
REQUIRED = ("ip", "noise", "riot")
LABEL = "GreyNoise"
SNAPSHOT_NOTE = (
    "served the operator-supplied GreyNoise snapshot file (CYBERAU_GREYNOISE_SNAPSHOT), "
    "not a live fetch"
)
_PACKAGE = Path(__file__).resolve().parents[2]
_RESPONSE_SCHEMA = _PACKAGE / "schema" / "greynoise_ip.response.json"
_TRANSPORT = None
_SLEEP = time.sleep
_LIMIT_SLEEP = time.sleep
_CLOCK = time.monotonic
# One retry keeps a daily-quota 429 with a long Retry-After near 60 s, under the 120 s tool timeout.
_RETRIES = 1
_TTL = 24 * 3600
_CLASSIFICATIONS = {"benign", "malicious", "unknown"}
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_LINK = re.compile(r"https://viz\.greynoise\.io/[A-Za-z0-9._~:/-]*")
_NON_PUBLIC = tuple(
    ipaddress.ip_network(item)
    for item in ("10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)


def greynoise_ip(ip: str) -> dict:
    problem = _validate_ip(ip)
    if problem:
        return _envelope(None, "snapshot", warnings=(problem,))
    address = _parse_ip(ip).compressed
    payload, cache, warning = _fetch(address)
    if warning:
        return _envelope(None, cache, warnings=(warning,))
    if payload is None:
        return _envelope(None, cache, warnings=("GreyNoise response was not usable",))
    drift = schema_drift(payload)
    if drift:
        return _envelope(None, cache, warnings=(drift,))
    if not _same_ip(payload.get("ip"), address):
        return _envelope(
            None,
            cache,
            payload,
            warnings=("no GreyNoise record for this IP in the offline snapshot or cache",),
        )
    if _not_observed(payload):
        return _envelope(None, cache, payload, warnings=_not_observed_warning(payload, cache))
    record = _record(payload)
    _persist(record)
    return _envelope(record, cache, payload)


def connector() -> Connector:
    return _GreyNoiseConnector()


class _GreyNoiseConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="greynoise",
            server_name="greynoise",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "greynoise_ip",
                    "GreyNoise community classification for an IP.",
                    greynoise_ip,
                )
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            if not os.environ.get("CYBERAU_GREYNOISE_SNAPSHOT"):
                return Probe(self.key, True, "schema ok, no local copy to check")
            payload = _load(_snapshot_text())
            problem = schema_drift(payload or {})
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        payload, _cache, warning = _fetch("1.1.1.1", force_live=True)
        if warning:
            return Probe(self.key, False, warning)
        problem = schema_drift(payload or {})
        if problem:
            return Probe(self.key, False, problem)
        if not _same_ip(payload.get("ip"), "1.1.1.1"):
            return Probe(self.key, False, "live probe returned a different IP")
        if _not_observed(payload):
            return Probe(self.key, True, "live ok; probe IP not observed")
        record = _record(payload)
        mismatch = _response_problem(record)
        if mismatch:
            return Probe(self.key, False, mismatch)
        return Probe(self.key, True, "live ok")


def schema_drift(payload: dict) -> str | None:
    if not isinstance(payload, dict):
        return "GreyNoise payload was not an object"
    missing = [name for name in REQUIRED if name not in payload]
    if missing:
        return "GreyNoise schema drift, missing " + ", ".join(missing)
    if not isinstance(payload.get("ip"), str):
        return "GreyNoise schema drift, missing ip"
    if not isinstance(payload.get("noise"), bool) or not isinstance(payload.get("riot"), bool):
        return "GreyNoise schema drift, noise and riot must be booleans"
    return None


def _fetch(ip: str, *, force_live: bool = False) -> tuple[dict | None, str, str]:
    url = _url(ip)
    snapshot = os.environ.get("CYBERAU_GREYNOISE_SNAPSHOT")
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    data_dir = _data_dir()
    cache = HttpCache(data_dir / "http_cache.sqlite")
    secret = lookup("GREYNOISE_API_KEY")
    scope = "keyed" if secret else "anonymous"
    cache_key = cache.key("GET", url, None, b"", scope)
    if snapshot and not force_live:
        payload, problem = _read(Path(snapshot))
        if problem:
            return None, "snapshot", problem
        return payload, "snapshot", ""
    cached = cache.get(cache_key)
    if cached and not force_live and (offline or cache.fresh(cached)):
        state = "hit" if cache.fresh(cached) else "stale"
        return _load(cached.body.decode("utf-8")), state, ""
    if offline:
        return None, "snapshot", unavailable(LABEL, "offline mode and no cached copy")
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    headers = {"key": secret} if secret else None
    client = HttpClient(
        "greynoise",
        policy=EgressPolicy(allowlist, "greynoise"),
        cache=cache,
        limiter=RateLimiter(data_dir / "rate_limit.sqlite", clock=_CLOCK, sleeper=_LIMIT_SLEEP),
        user_agent=USER_AGENT,
        rate=1,
        burst=1,
        window="rolling",
        timeout=30,
        retries=_RETRIES,
        auth_scope=scope,
        transport=_TRANSPORT,
        sleeper=_SLEEP,
    )
    try:
        response = client.get(url, headers=headers, ttl=_TTL, skip_cache=force_live)
    except (HttpError, EgressDenied, TimeoutError) as exc:
        if not force_live:
            cached = cache.get(cache_key)
            if cached:
                return _load(cached.body.decode("utf-8")), "stale", ""
            reason = f"the live fetch failed ({_clean(exc, secret)})"
            return None, "snapshot", unavailable(LABEL, reason)
        return None, "snapshot", _clean(exc, secret)
    finally:
        client.close()
    if response.status in (401, 403):
        reason = f"GreyNoise refused the request ({response.status}). Check GREYNOISE_API_KEY"
        return None, response.cache, unavailable(LABEL, reason)
    if response.status == 429:
        wait = response.headers.get("retry-after", "").strip()
        hint = f". Retry after {wait} seconds" if wait.isdigit() else ""
        return None, response.cache, unavailable(LABEL, "GreyNoise rate limit reached" + hint)
    if response.status >= 400 and response.status != 404:
        reason = f"GreyNoise upstream status {response.status}"
        return None, response.cache, unavailable(LABEL, reason)
    payload = _load(response.body.decode("utf-8"))
    if payload is None:
        return None, response.cache, "GreyNoise response was not usable"
    return payload, response.cache, ""


def _record(payload: dict) -> dict:
    name = str(payload.get("name") or "")
    message = str(payload.get("message") or "")
    return {
        "ip": _checked(payload.get("ip"), lambda text: _parse_ip(text) is not None),
        "noise": bool(payload["noise"]),
        "riot": bool(payload["riot"]),
        "classification": _checked(
            payload.get("classification"), lambda text: text in _CLASSIFICATIONS
        ),
        "name": untrusted_text(name, "greynoise") if name else "",
        "link": _checked(payload.get("link"), lambda text: bool(_LINK.fullmatch(text))),
        "last_seen": _checked(payload.get("last_seen"), lambda text: bool(_DATE.fullmatch(text))),
        "message": untrusted_text(message, "greynoise") if message else "",
    }


def _checked(value, expected) -> str:
    """Pass a value that has the expected shape, wrap anything else as untrusted text."""
    text = str(value or "")
    if not text or expected(text):
        return text
    return untrusted_text(text, "greynoise")


def _not_observed(payload: dict) -> bool:
    if payload.get("noise") or payload.get("riot"):
        return False
    return not str(payload.get("classification") or "").strip()


def _not_observed_warning(payload: dict, cache: str) -> tuple[str, ...]:
    raw = str(
        payload.get("message")
        or "IP not observed scanning the internet or contained in the RIOT data set."
    )
    notes = [untrusted_text(raw, "greynoise")]
    if cache == "snapshot":
        notes.append("no GreyNoise record for this IP in the offline snapshot or cache")
    return tuple(notes)


def _response_problem(record: dict) -> str | None:
    schema = json.loads(_RESPONSE_SCHEMA.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(record, schema)
    except jsonschema.ValidationError as exc:
        return "GreyNoise response schema: " + exc.message
    return None


def _persist(record: dict) -> None:
    directory = _data_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "greynoise-observations.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def _parse_ip(text: str):
    try:
        address = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    return None if getattr(address, "scope_id", None) else address


def _validate_ip(ip: str) -> str:
    if not isinstance(ip, str) or not ip.strip():
        return "ip must be an IPv4 or IPv6 address"
    address = _parse_ip(ip)
    if address is None:
        return "ip must be an IPv4 or IPv6 address"
    checked = getattr(address, "ipv4_mapped", None) or address
    if (
        checked.is_loopback
        or checked.is_link_local
        or checked.is_multicast
        or checked.is_unspecified
        or any(checked in network for network in _NON_PUBLIC)
    ):
        return "ip must be a public address. GreyNoise only classifies internet hosts"
    return ""


def _same_ip(left, right: str) -> bool:
    try:
        return ipaddress.ip_address(str(left)) == ipaddress.ip_address(right)
    except ValueError:
        return False


def _url(ip: str) -> str:
    return f"{COMMUNITY_API}/{ip}"


def _data_dir() -> Path:
    return Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-greynoise"))


def _snapshot_text() -> str:
    """Read the operator-supplied snapshot. Nothing shipped in the repo is read."""
    return Path(os.environ["CYBERAU_GREYNOISE_SNAPSHOT"]).read_text(encoding="utf-8")


def _read(path: Path) -> tuple[dict | None, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None, "GreyNoise snapshot could not be read"
    payload = _load(text)
    if payload is None:
        return None, "GreyNoise response was not usable"
    return payload, ""


def _load(text: str) -> dict | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _envelope(
    data,
    cache: str,
    payload: dict | None = None,
    warnings: tuple[str, ...] = (),
) -> dict:
    as_of = None
    if payload and _DATE.fullmatch(str(payload.get("last_seen") or "")):
        as_of = str(payload["last_seen"])
    if payload is not None and cache == "snapshot":
        warnings = (*warnings, SNAPSHOT_NOTE)
    return envelope(
        "greynoise",
        data,
        urls=[COMMUNITY_API],
        cache=cache,
        data_as_of=as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _clean(exc: BaseException, secret: str | None) -> str:
    message = redact(str(exc))
    if secret:
        message = message.replace(secret, "[REDACTED]")
    return message


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("greynoise", connector)
