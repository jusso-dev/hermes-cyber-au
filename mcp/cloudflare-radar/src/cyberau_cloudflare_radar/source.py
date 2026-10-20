"""Read-only Cloudflare Radar telemetry through the Radar REST API.

Each tool makes one GET to api.cloudflare.com/client/v4/radar with a custom API token that
holds only Account > Radar > Read. Results are trimmed to the fields an analyst needs. Free
text such as outage descriptions and organisation names is wrapped as untrusted.
"""

import json
import os
import re
import time
from pathlib import Path
from urllib.parse import quote, urlencode

import jsonschema
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, safe_url, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from cyberau_common.snapshot import unavailable

KEY = "cloudflare-radar"
SERVER = "cloudflare_radar"
API = "https://api.cloudflare.com/client/v4/radar"
TOKEN_ENV = "CLOUDFLARE_RADAR_API_TOKEN"
ATTRIBUTION = "Source: Cloudflare Radar (CC BY-NC 4.0)."
LABEL = "Cloudflare Radar"
DATE_RANGES = ("1d", "2d", "7d", "14d", "28d", "12w", "24w", "52w")
L7_DIMENSIONS = (
    "http_method",
    "http_version",
    "ip_version",
    "managed_rules",
    "mitigation_product",
    "bot_class",
)
_PACKAGE = Path(__file__).resolve().parents[2]
_TRANSPORT = None
_SLEEP = time.sleep
_LIMIT_SLEEP = time.sleep
_CLOCK = time.monotonic
_RETRIES = 1
_TTL = 15 * 60
_LOCATION = re.compile(r"[A-Za-z]{2}")
_DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
# Codes, numbers, timestamps, domains and prefixes pass as they are. Anything with a space or
# other punctuation is free text and is wrapped as untrusted.
_PLAIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/+-]{0,99}")


def get_radar_annotations_outages(
    location: str | None = None,
    asn: int | None = None,
    date_range: str = "7d",
    limit: int = 10,
) -> dict:
    problem = (
        _check_location(location)
        or _check_asn(asn)
        or _check_range(date_range)
        or _check_limit(limit, 50)
    )
    if problem:
        return _envelope(None, "snapshot", warnings=(problem,))
    params = {"dateRange": date_range, "limit": limit, "location": _upper(location), "asn": asn}
    result, cache, warning = _call("/annotations/outages", params)
    if result is None:
        return _envelope(None, cache, warnings=(warning,))
    rows = [_outage(item) for item in _list(result.get("annotations"))]
    notes = () if rows else ("no outages in this window",)
    return _envelope({"date_range": date_range, "outages": rows}, cache, warnings=notes)


def get_radar_attacks_layer7_summary(
    dimension: str = "mitigation_product",
    location: str | None = None,
    date_range: str = "7d",
) -> dict:
    problem = _check_location(location) or _check_range(date_range)
    if dimension not in L7_DIMENSIONS:
        problem = problem or "dimension must be one of " + ", ".join(L7_DIMENSIONS)
    if problem:
        return _envelope(None, "snapshot", warnings=(problem,))
    params = {"dateRange": date_range, "location": _upper(location)}
    result, cache, warning = _call(f"/attacks/layer7/summary/{dimension}", params)
    if result is None:
        return _envelope(None, cache, warnings=(warning,))
    summary = result.get("summary_0")
    if not isinstance(summary, dict):
        return _envelope(None, cache, warnings=("Radar response had no summary",))
    meta = result.get("meta") if isinstance(result.get("meta"), dict) else {}
    data = {
        "dimension": dimension,
        "location": _upper(location) or "worldwide",
        "share_percent": {
            str(key): _number(value)
            for key, value in summary.items()
            if _PLAIN.fullmatch(str(key)) and _number(value) is not None
        },
        "window": _window(meta),
        "last_updated": _plain(meta.get("lastUpdated")),
    }
    return _envelope(data, cache, data_as_of=_as_of(data["last_updated"]))


def get_radar_bgp_hijacks_events(
    involved_asn: int | None = None,
    involved_country: str | None = None,
    date_range: str = "7d",
    limit: int = 10,
) -> dict:
    return _bgp(
        "/bgp/hijacks/events",
        involved_asn,
        involved_country,
        date_range,
        limit,
        (
            "id",
            "hijacker_asn",
            "hijacker_country",
            "victim_asns",
            "victim_countries",
            "prefixes",
            "min_hijack_ts",
            "max_hijack_ts",
            "duration",
            "confidence_score",
            "is_stale",
            "hijack_msgs_count",
            "peer_ip_count",
        ),
    )


def get_radar_bgp_leaks_events(
    involved_asn: int | None = None,
    involved_country: str | None = None,
    date_range: str = "7d",
    limit: int = 10,
) -> dict:
    return _bgp(
        "/bgp/leaks/events",
        involved_asn,
        involved_country,
        date_range,
        limit,
        (
            "id",
            "leak_asn",
            "leak_seg",
            "leak_type",
            "countries",
            "detected_ts",
            "min_ts",
            "max_ts",
            "finished",
            "leak_count",
            "prefix_count",
            "origin_count",
            "peer_count",
        ),
    )


def get_radar_ranking_top(location: str | None = None, limit: int = 10) -> dict:
    problem = _check_location(location) or _check_limit(limit, 100)
    if problem:
        return _envelope(None, "snapshot", warnings=(problem,))
    params = {"limit": limit, "location": _upper(location)}
    result, cache, warning = _call("/ranking/top", params)
    if result is None:
        return _envelope(None, cache, warnings=(warning,))
    rows = [
        {"rank": _number(item.get("rank")), "domain": _plain(item.get("domain"))}
        for item in _list(result.get("top_0"))
    ]
    meta = result.get("meta") if isinstance(result.get("meta"), dict) else {}
    top_meta = meta.get("top_0") if isinstance(meta.get("top_0"), dict) else {}
    day = _plain(top_meta.get("date"))
    data = {"location": _upper(location) or "worldwide", "date": day, "domains": rows}
    return _envelope(data, cache, data_as_of=_as_of(day))


def get_radar_ranking_domain(domain: str) -> dict:
    name = str(domain or "").strip().lower().rstrip(".")
    if not _DOMAIN.fullmatch(name):
        return _envelope(
            None, "snapshot", warnings=("domain must be a hostname such as example.com",)
        )
    result, cache, warning = _call(f"/ranking/domain/{quote(name)}", {})
    if result is None:
        return _envelope(None, cache, warnings=(warning,))
    details = result.get("details_0")
    if not isinstance(details, dict):
        return _envelope(None, cache, warnings=("Radar response had no domain details",))
    categories = [
        _text(item.get("name"))
        for item in _list(details.get("categories"))
        if item.get("name") is not None
    ]
    data = {
        "domain": name,
        "rank": _number(details.get("rank")),
        "bucket": _plain(details.get("bucket")),
        "categories": categories,
        "window": _window(result.get("meta") if isinstance(result.get("meta"), dict) else {}),
    }
    notes = () if data["rank"] is not None else ("domain is not in the Radar top ranking",)
    return _envelope(data, cache, warnings=notes)


TOOLS = (
    (
        get_radar_annotations_outages,
        "Internet outages and traffic anomalies from Cloudflare Radar, optionally for one "
        "country (ISO code such as AU) or ASN.",
    ),
    (
        get_radar_attacks_layer7_summary,
        "Share of layer 7 (HTTP) attack traffic by one dimension, such as mitigation product "
        "or HTTP method, worldwide or targeting one country.",
    ),
    (
        get_radar_bgp_hijacks_events,
        "Recent BGP origin hijack events, optionally involving one ASN or country.",
    ),
    (
        get_radar_bgp_leaks_events,
        "Recent BGP route leak events, optionally involving one ASN or country.",
    ),
    (
        get_radar_ranking_top,
        "Top domains by Cloudflare Radar popularity rank, worldwide or for one country.",
    ),
    (
        get_radar_ranking_domain,
        "Cloudflare Radar popularity rank, rank bucket and categories for one domain.",
    ),
)


def connector() -> Connector:
    return _RadarConnector()


class _RadarConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key=KEY,
            server_name=SERVER,
            attribution=ATTRIBUTION,
            tools=[ToolSpec(fn.__name__, text, fn) for fn, text in TOOLS],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if not live:
            return Probe(self.key, True, "offline ok")
        if lookup(TOKEN_ENV) is None:
            return Probe(self.key, False, f"{TOKEN_ENV} is not set, so no live check was made")
        # A forced live call proves the token works. The tool calls after it then read
        # that fresh copy and check it against the stored response schemas.
        probes = (
            ("/annotations/outages", {"dateRange": "7d", "limit": 1}),
            ("/ranking/top", {"limit": 1}),
        )
        for path, params in probes:
            result, _cache, warning = _call_live(path, params)
            if result is None:
                return Probe(self.key, False, warning)
        for name, fn in (
            ("get_radar_annotations_outages", lambda: get_radar_annotations_outages(limit=1)),
            ("get_radar_ranking_top", lambda: get_radar_ranking_top(limit=1)),
        ):
            problem = response_problem(name, fn().get("data"))
            if problem:
                return Probe(self.key, False, problem)
        return Probe(self.key, True, "live ok")


def response_problem(tool: str, data) -> str | None:
    """Validate one tool's data against its stored response schema."""
    schema = json.loads((_PACKAGE / "schema" / f"{tool}.response.json").read_text("utf-8"))
    try:
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as exc:
        return f"{LABEL} {tool} response schema: {exc.message}"
    return None


def _bgp(
    path: str,
    involved_asn: int | None,
    involved_country: str | None,
    date_range: str,
    limit: int,
    fields: tuple[str, ...],
) -> dict:
    problem = (
        _check_asn(involved_asn)
        or _check_location(involved_country)
        or _check_range(date_range)
        or _check_limit(limit, 50)
    )
    if problem:
        return _envelope(None, "snapshot", warnings=(problem,))
    params = {
        "dateRange": date_range,
        "per_page": limit,
        "involvedAsn": involved_asn,
        "involvedCountry": _upper(involved_country),
    }
    result, cache, warning = _call(path, params)
    if result is None:
        return _envelope(None, cache, warnings=(warning,))
    events = [
        {name: _clean(item[name]) for name in fields if name in item}
        for item in _list(result.get("events"))
    ]
    asns = [
        {
            "asn": _number(item.get("asn")),
            "org_name": _text(item.get("org_name")),
            "country_code": _plain(item.get("country_code")),
        }
        for item in _list(result.get("asn_info"))
    ]
    notes = () if events else ("no events in this window",)
    return _envelope(
        {"date_range": date_range, "events": events, "asn_info": asns}, cache, warnings=notes
    )


def _outage(item: dict) -> dict:
    outage = item.get("outage") if isinstance(item.get("outage"), dict) else {}
    return {
        "id": _plain(item.get("id")),
        "start": _plain(item.get("startDate")),
        "end": _plain(item.get("endDate")),
        "event_type": _plain(item.get("eventType")),
        "cause": _clean(outage.get("outageCause")),
        "type": _clean(outage.get("outageType")),
        "locations": [_plain(code) for code in _list_any(item.get("locations"))],
        "asns": [_number(asn) for asn in _list_any(item.get("asns"))],
        "scope": _text(item.get("scope")),
        "description": _text(item.get("description")),
        "linked_url": safe_url(item.get("linkedUrl"), schemes=("https",)),
    }


def _call(path: str, params: dict) -> tuple[dict | None, str, str]:
    return _fetch(path, params, force_live=False)


def _call_live(path: str, params: dict) -> tuple[dict | None, str, str]:
    return _fetch(path, params, force_live=True)


def _fetch(path: str, params: dict, *, force_live: bool) -> tuple[dict | None, str, str]:
    query = {key: value for key, value in params.items() if value is not None}
    query["format"] = "json"
    url = f"{API}{path}?{urlencode(sorted(query.items()))}"
    data_dir = _data_dir()
    cache = HttpCache(data_dir / "http_cache.sqlite")
    cache_key = cache.key("GET", url, None, b"", "keyed")
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    cached = cache.get(cache_key)
    if cached and not force_live and (offline or cache.fresh(cached)):
        state = "hit" if cache.fresh(cached) else "stale"
        return _result(cached.body), state, ""
    if offline:
        return None, "snapshot", unavailable(LABEL, "offline mode and no cached copy")
    secret = lookup(TOKEN_ENV)
    if secret is None:
        return None, "snapshot", unavailable(LABEL, f"{TOKEN_ENV} is not set")
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    client = HttpClient(
        KEY,
        policy=EgressPolicy(allowlist, KEY),
        cache=cache,
        limiter=RateLimiter(data_dir / "rate_limit.sqlite", clock=_CLOCK, sleeper=_LIMIT_SLEEP),
        user_agent=USER_AGENT,
        rate=2,
        burst=4,
        window="rolling",
        timeout=30,
        retries=_RETRIES,
        auth_scope="keyed",
        transport=_TRANSPORT,
        sleeper=_SLEEP,
    )
    try:
        response = client.get(
            url, headers={"Authorization": f"Bearer {secret}"}, ttl=_TTL, skip_cache=force_live
        )
    except (HttpError, EgressDenied, TimeoutError) as exc:
        if not force_live and cached:
            return _result(cached.body), "stale", ""
        reason = f"the live fetch failed ({_redact(exc, secret)})"
        return None, "snapshot", unavailable(LABEL, reason)
    finally:
        client.close()
    if response.status in (401, 403):
        reason = (
            f"Cloudflare refused the token ({response.status}). Check {TOKEN_ENV} holds a "
            "custom token with only Account > Radar > Read"
        )
        return None, response.cache, unavailable(LABEL, reason)
    if response.status == 429:
        wait = response.headers.get("retry-after", "").strip()
        hint = f". Retry after {wait} seconds" if wait.isdigit() else ""
        return None, response.cache, unavailable(LABEL, "Radar rate limit reached" + hint)
    if response.status >= 400:
        return None, response.cache, unavailable(LABEL, f"upstream status {response.status}")
    result = _result(response.body)
    if result is None:
        return None, response.cache, unavailable(LABEL, "the response was not usable")
    return result, response.cache, ""


def _result(body: bytes) -> dict | None:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("success") is not True:
        return None
    result = payload.get("result")
    return result if isinstance(result, dict) else None


def _clean(value):
    """Keep numbers, booleans and plain codes. Wrap free text. Recurse into lists."""
    if isinstance(value, list):
        return [_clean(item) for item in value[:50]]
    if isinstance(value, bool | int | float) or value is None:
        return value
    if isinstance(value, str):
        return value if _PLAIN.fullmatch(value) else untrusted_text(value, KEY, 500)
    return None


def _plain(value) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if _PLAIN.fullmatch(text) else untrusted_text(text, KEY, 200)


def _text(value) -> str | None:
    if value is None or str(value).strip() == "":
        return None
    return untrusted_text(str(value), KEY, 500)


def _number(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return value
    try:
        number = float(str(value))
    except ValueError:
        return None
    return int(number) if number.is_integer() and "." not in str(value) else number


def _window(meta: dict) -> dict | None:
    ranges = meta.get("dateRange")
    if not isinstance(ranges, list) or not ranges or not isinstance(ranges[0], dict):
        return None
    return {"start": _plain(ranges[0].get("startTime")), "end": _plain(ranges[0].get("endTime"))}


def _as_of(value: str | None) -> str | None:
    if value and re.match(r"\d{4}-\d{2}-\d{2}", value):
        return value[:10]
    return None


def _list(value) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _list_any(value) -> list:
    return value[:50] if isinstance(value, list) else []


def _upper(value: str | None) -> str | None:
    return value.strip().upper() if isinstance(value, str) and value.strip() else None


def _check_location(value: str | None) -> str:
    if value is None or (isinstance(value, str) and not value.strip()):
        return ""
    if not isinstance(value, str) or not _LOCATION.fullmatch(value.strip()):
        return "location must be a two-letter country code such as AU"
    return ""


def _check_asn(value: int | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 2**32:
        return "asn must be a positive autonomous system number"
    return ""


def _check_range(value: str) -> str:
    return "" if value in DATE_RANGES else "date_range must be one of " + ", ".join(DATE_RANGES)


def _check_limit(value: int, most: int) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= most:
        return f"limit must be between 1 and {most}"
    return ""


def _envelope(
    data,
    cache: str,
    *,
    data_as_of: str | None = None,
    warnings: tuple[str, ...] = (),
) -> dict:
    return envelope(
        KEY,
        data,
        urls=[API],
        cache=cache,
        data_as_of=data_as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _redact(exc: BaseException, secret: str | None) -> str:
    message = redact(str(exc))
    return message.replace(secret, "[REDACTED]") if secret else message


def _data_dir() -> Path:
    return Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-cloudflare-radar"))


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector(KEY, connector)
