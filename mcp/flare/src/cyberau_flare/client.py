"""Flare REST client. Tokens stay in memory. Search calls stay at one a second."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_premium.caching import cache_for_terms
from cyberau_premium.catalog import get_vendor
from cyberau_premium.paths import data_dir

from cyberau_flare.quota import record_global_search

LOGGER = logging.getLogger("cyberau.flare")

API = "https://api.flare.io"
TOKEN_URL = f"{API}/tokens/generate"
TOKEN_TEST_URL = f"{API}/tokens/test"
TENANT_EVENTS_URL = f"{API}/firework/v4/events/tenant/_search"
IDENTIFIERS_URL = f"{API}/firework/v4/identifiers/"
CREDENTIALS_URL = f"{API}/firework/v4/credentials/global/_search"

TOKEN_TTL_S = 3600
TOKEN_SKEW_S = 60
SEARCH_RATE = 1.0
SEARCH_BURST = 1
RATE_LIMIT_WAIT_S = 10.0
EVENT_TTL_S = 300
IDENTIFIER_TTL_S = 3600
PAGE_SIZE = 100
_PARTIAL = "Flare has more results than were read. The list is partial."

# Tests inject these. Production leaves them unset.
TRANSPORT = None
SLEEPER = None
CLOCK = None
RESOLVER = None

_TOKEN: str | None = None
_TOKEN_EXPIRES_AT = 0.0
_CACHE: HttpCache | None = None


@dataclass
class Fetch:
    items: list
    cache: str
    warnings: tuple[str, ...]
    headers: dict[str, str]
    next_cursor: str | None = None


_NO_COPY = "offline or unreachable, and there is no cached copy"
_NO_FIXTURE = "the CYBERAU_FLARE_FIXTURES directory has no usable file for this call"


def reset_token() -> None:
    """Drop the in-memory token and session cache. Used between tests."""
    global _TOKEN, _TOKEN_EXPIRES_AT, _CACHE
    _TOKEN = None
    _TOKEN_EXPIRES_AT = 0.0
    if _CACHE is not None:
        _CACHE.clear_session()
    _CACHE = None


def package_root() -> Path:
    return Path(__file__).resolve().parents[2]


def allowlist_path() -> Path:
    override = lookup("CYBERAU_EGRESS_ALLOWLIST")
    if override:
        return Path(override)
    return package_root().parent / "egress-allowlist.yaml"


def fixture_dir() -> Path | None:
    if lookup("CYBERAU_FLARE_HTTP") == "1":
        return None
    raw = lookup("CYBERAU_FLARE_FIXTURES")
    if raw is None:
        return None
    return Path(raw)


def _whole(text: str | None) -> int | None:
    """Parse ASCII digits only. str.isdigit() also accepts forms int() rejects."""
    if text is None or not text.isascii() or not text.isdigit():
        return None
    return int(text)


def missing_key_warning() -> str | None:
    if lookup("FLARE_API_KEY") is None:
        return "Flare is not configured. Set FLARE_API_KEY."
    tenant = lookup("FLARE_TENANT_ID")
    if tenant is not None and _whole(tenant) is None:
        return "FLARE_TENANT_ID must be a whole number."
    return None


def domain_query(domain: str, *, since: str | None, size: int) -> dict:
    """Global credential search by domain only. Email and password queries are not built."""
    body: dict = {"query": {"type": "domain", "fqdn": domain}, "size": size}
    if since:
        body["filters"] = {"imported_at": {"gte": since}}
    return body


def _clock() -> float:
    if CLOCK is not None:
        return float(CLOCK())
    return time.time()


def _sleep(seconds: float) -> None:
    if SLEEPER is not None:
        SLEEPER(seconds)
        return
    time.sleep(seconds)


def _scrub(message: str) -> str:
    text = redact(message)
    key = lookup("FLARE_API_KEY")
    if key:
        text = text.replace(key, "[REDACTED]")
    if _TOKEN:
        text = text.replace(_TOKEN, "[REDACTED]")
    return text


def _session_cache() -> HttpCache:
    global _CACHE
    if _CACHE is None:
        _CACHE = cache_for_terms(
            data_dir() / "flare-http.sqlite",
            get_vendor("flare").terms,
            now=CLOCK,
        )
    return _CACHE


def _limiter() -> RateLimiter:
    kwargs = {}
    if CLOCK is not None:
        kwargs["clock"] = CLOCK
    if SLEEPER is not None:
        kwargs["sleeper"] = SLEEPER
    return RateLimiter(data_dir() / "rate_limit.sqlite", **kwargs)


def _policy() -> EgressPolicy:
    if RESOLVER is not None:
        return EgressPolicy(allowlist_path(), "flare", resolver=RESOLVER)
    return EgressPolicy(allowlist_path(), "flare")


def _max_pages() -> int:
    return int(get_vendor("flare").max_pages)


def _decode(body: bytes):
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _status_warning(status: int, payload) -> str:
    code = ""
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict) and isinstance(error.get("code"), str):
            code = error["code"]
    suffix = f" {code}" if code else ""
    if status in {401, 403}:
        return f"Flare refused the call ({status}{suffix}). Check FLARE_API_KEY."
    if status == 429:
        return (
            f"Flare rate limit reached ({status}{suffix}). Wait {int(RATE_LIMIT_WAIT_S)} seconds."
        )
    return f"Flare upstream status {status}{suffix}."


def _retry_wait(headers: dict[str, str]) -> float:
    raw = headers.get("retry-after")
    if raw:
        try:
            return max(0.0, min(60.0, float(raw)))
        except ValueError:
            return RATE_LIMIT_WAIT_S
    return RATE_LIMIT_WAIT_S


def _fixture_name(url: str) -> str | None:
    if url.endswith("/tokens/generate"):
        return "token_generate_synthetic.json"
    if url.endswith("/tokens/test"):
        return "token_test_synthetic.json"
    if url.endswith("/events/tenant/_search"):
        return "flare_tenant_exposure_synthetic.json"
    if "/events/identifiers/" in url:
        return "flare_identifier_events_synthetic.json"
    if url.rstrip("/").endswith("/identifiers"):
        return "flare_identifiers_synthetic.json"
    if url.endswith("/credentials/global/_search"):
        return "flare_domain_credentials_synthetic.json"
    return None


def _from_fixture(url: str) -> Fetch:
    directory = fixture_dir()
    name = _fixture_name(url)
    if directory is None or name is None:
        return Fetch([], "snapshot", (_NO_FIXTURE,), {})
    path = directory / name
    if not path.is_file():
        return Fetch([], "snapshot", (_NO_FIXTURE,), {})
    payload = _decode(path.read_bytes())
    if payload is None:
        return Fetch([], "snapshot", ("Flare payload was not usable",), {})
    items = payload.get("items")
    if "items" in payload and not isinstance(items, list):
        return Fetch([], "snapshot", ("Flare payload was not usable",), {})
    cursor = payload.get("next") if isinstance(payload.get("next"), str) else None
    return Fetch(items or [], "snapshot", (), {}, cursor)


def _open(cache: HttpCache) -> HttpClient:
    offline = lookup("CYBERAU_OFFLINE") == "1"
    return HttpClient(
        "flare",
        policy=_policy(),
        cache=cache,
        limiter=_limiter(),
        user_agent=USER_AGENT,
        rate=SEARCH_RATE,
        burst=SEARCH_BURST,
        window="rolling",
        timeout=30,
        retries=0,
        auth_scope="flare",
        offline=offline,
        transport=TRANSPORT,
        sleeper=_sleep,
    )


def _send(
    method: str,
    url: str,
    *,
    body: dict | None,
    params,
    headers: dict,
    ttl: int,
    cache: HttpCache,
):
    client = _open(cache)
    try:
        if method == "GET":
            return client.get(url, params=params, headers=headers, ttl=ttl)
        return client.post_json(url, body or {}, headers=headers, ttl=ttl)
    finally:
        client.close()


def _issue_token() -> tuple[str | None, str | None]:
    """Exchange the API key for a bearer token. The values are not logged."""
    global _TOKEN, _TOKEN_EXPIRES_AT
    key = lookup("FLARE_API_KEY")
    if key is None:
        return None, "Flare is not configured. Set FLARE_API_KEY."
    directory = fixture_dir()
    if directory is not None:
        payload = _decode((directory / "token_generate_synthetic.json").read_bytes())
        token = payload.get("token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            return None, "Flare payload was not usable"
        _TOKEN = token
        _TOKEN_EXPIRES_AT = _clock() + TOKEN_TTL_S
        return token, None
    tenant = _whole(lookup("FLARE_TENANT_ID"))
    body = {"tenant_id": tenant} if tenant is not None else {}
    try:
        response = _send(
            "POST",
            TOKEN_URL,
            body=body,
            params=None,
            headers={"Authorization": key},
            ttl=0,
            cache=HttpCache(data_dir() / "flare-token.sqlite", persistence="none"),
        )
    except (HttpError, EgressDenied, httpx.HTTPError) as exc:
        text = _scrub(str(exc))
        if lookup("CYBERAU_OFFLINE") == "1" or "no cache" in text:
            return None, _NO_COPY
        return None, text or "unavailable"
    payload = _decode(response.body)
    if response.status in {401, 403}:
        return None, _status_warning(response.status, payload)
    if response.status >= 400 or not isinstance(payload, dict):
        return None, _status_warning(response.status, payload)
    token = payload.get("token")
    if not isinstance(token, str) or not token:
        return None, "Flare payload was not usable"
    _TOKEN = token
    _TOKEN_EXPIRES_AT = _clock() + TOKEN_TTL_S
    LOGGER.info("Flare token refreshed")
    return token, None


def _bearer(force: bool = False) -> tuple[str | None, str | None]:
    if not force and _TOKEN and _clock() < _TOKEN_EXPIRES_AT - TOKEN_SKEW_S:
        return _TOKEN, None
    return _issue_token()


def _call(
    method: str,
    url: str,
    *,
    body: dict | None = None,
    params: dict | None = None,
    ttl: int,
    auth_attempt: int = 0,
    limit_attempt: int = 0,
    count_global: bool = False,
) -> Fetch:
    directory = fixture_dir()
    if directory is not None:
        return _from_fixture(url)
    token, problem = _bearer()
    if problem or token is None:
        detail = problem or "Flare is not configured. Set FLARE_API_KEY."
        return Fetch([], "snapshot", (detail,), {})
    try:
        response = _send(
            method,
            url,
            body=body,
            params=params,
            headers={"Authorization": f"Bearer {token}"},
            ttl=ttl,
            cache=_session_cache(),
        )
    except (HttpError, EgressDenied, httpx.HTTPError) as exc:
        text = _scrub(str(exc))
        if lookup("CYBERAU_OFFLINE") == "1" or "no cache" in text:
            return Fetch([], "snapshot", (_NO_COPY,), {})
        return Fetch([], "snapshot", (text or "unavailable",), {})
    payload = _decode(response.body)
    headers = {name.lower(): value for name, value in response.headers.items()}
    if response.status == 401 and auth_attempt < 1:
        LOGGER.info("Flare token rejected, refreshing once")
        refreshed, refresh_problem = _bearer(force=True)
        if refreshed is None:
            return Fetch(
                [],
                response.cache,
                (refresh_problem or _status_warning(401, payload),),
                headers,
            )
        return _call(
            method,
            url,
            body=body,
            params=params,
            ttl=ttl,
            auth_attempt=auth_attempt + 1,
            limit_attempt=limit_attempt,
            count_global=count_global,
        )
    if response.status == 429 and limit_attempt < 1:
        wait = _retry_wait(headers)
        LOGGER.info("Flare rate limit, waiting")
        _sleep(wait)
        return _call(
            method,
            url,
            body=body,
            params=params,
            ttl=ttl,
            auth_attempt=auth_attempt,
            limit_attempt=limit_attempt + 1,
            count_global=count_global,
        )
    if response.status >= 400:
        return Fetch([], response.cache, (_status_warning(response.status, payload),), headers)
    if payload is None:
        return Fetch([], response.cache, ("Flare payload was not usable",), headers)
    if "items" in payload and not isinstance(payload.get("items"), list):
        return Fetch([], response.cache, ("Flare payload was not usable",), headers)
    items = payload.get("items", [])
    cursor = payload.get("next") if isinstance(payload.get("next"), str) else None
    if count_global and response.cache == "miss":
        remaining = _whole(headers.get("x-flare-global-searches-remaining"))
        record_global_search(remaining)
    return Fetch(items if isinstance(items, list) else [], response.cache, (), headers, cursor)


def _post_pages(
    url: str,
    body: dict,
    *,
    limit: int,
    ttl: int,
    count_global: bool = False,
    gate=None,
) -> Fetch:
    """Read pages up to `limit`. `gate` runs before each page after the first.

    Each Global Search page spends quota, so a gate that returns a message stops
    the read and the rows already fetched come back with that message.
    """
    problem = missing_key_warning()
    if problem:
        return Fetch([], "snapshot", (problem,), {})
    if fixture_dir() is not None:
        return _from_fixture(url)
    items: list = []
    cache = "miss"
    headers: dict[str, str] = {}
    cursor = None
    for index in range(_max_pages()):
        if len(items) >= limit:
            break
        if gate is not None and index > 0:
            stop = gate()
            if stop:
                return Fetch(items[:limit], cache, (f"{stop} Counts are partial.",), headers)
        page = dict(body)
        page["size"] = min(PAGE_SIZE, max(1, limit - len(items)))
        if cursor:
            page["from"] = cursor
        fetched = _call("POST", url, body=page, ttl=ttl, count_global=count_global)
        cache = fetched.cache
        headers = fetched.headers or headers
        if fetched.warnings:
            return Fetch(items[:limit], cache, fetched.warnings, headers)
        if not isinstance(fetched.items, list):
            return Fetch([], cache, ("Flare payload was not usable",), headers)
        items.extend(fetched.items)
        cursor = fetched.next_cursor
        if not cursor:
            break
    if cursor:
        return Fetch(items[:limit], cache, (_PARTIAL,), headers)
    return Fetch(items[:limit], cache, (), headers)


def fetch_tenant_events(body: dict, *, limit: int) -> Fetch:
    return _post_pages(TENANT_EVENTS_URL, body, limit=limit, ttl=EVENT_TTL_S)


def fetch_identifier_events(identifier_id: int, body: dict, *, limit: int) -> Fetch:
    url = f"{API}/firework/v4/events/identifiers/{identifier_id}/_search"
    return _post_pages(url, body, limit=limit, ttl=EVENT_TTL_S)


def fetch_identifiers() -> Fetch:
    problem = missing_key_warning()
    if problem:
        return Fetch([], "snapshot", (problem,), {})
    if fixture_dir() is not None:
        return _from_fixture(IDENTIFIERS_URL)
    fetched = _call("GET", IDENTIFIERS_URL, ttl=IDENTIFIER_TTL_S, params={"size": PAGE_SIZE})
    if fetched.next_cursor and not fetched.warnings:
        # Only the first page is read. A partial list would report monitored
        # identifiers as missing, so say so.
        return Fetch(fetched.items, fetched.cache, (_PARTIAL,), fetched.headers)
    return fetched


def fetch_domain_credentials(body: dict, *, gate=None) -> Fetch:
    return _post_pages(
        CREDENTIALS_URL,
        body,
        limit=PAGE_SIZE * _max_pages(),
        ttl=EVENT_TTL_S,
        count_global=True,
        gate=gate,
    )


def probe_token() -> tuple[bool, str]:
    problem = missing_key_warning()
    if problem:
        return False, problem
    if fixture_dir() is not None:
        return False, "fixture mode, not a live check"
    # ttl=0 so a cached copy is never fresh. A stale copy served after a failed
    # fetch comes back as hit or stale, and that is not a live answer.
    fetched = _call("GET", TOKEN_TEST_URL, ttl=0)
    if fetched.warnings:
        return False, fetched.warnings[0]
    if fetched.cache != "miss":
        return False, f"served from {fetched.cache} copy, not a live check"
    return True, "live ok"
