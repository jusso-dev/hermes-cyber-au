"""HTTP client with egress checks, caching, rate limits, and bounded retries."""

from __future__ import annotations

import datetime
import email.utils
import math
import random
from dataclasses import dataclass
from urllib.parse import urlencode

import httpcore
import httpx
from httpx._utils import get_environment_proxies

from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressPolicy, EgressUnresolved
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import SECRET_HEADER_NAMES, redact, redact_headers

_REDIRECTS = {301, 302, 303, 307, 308}


class HttpError(Exception):
    """A request failed and no stale cache could answer."""

    def __init__(self, message: object = "") -> None:
        text = message if isinstance(message, str) else str(message)
        super().__init__(redact(text))

    def __str__(self) -> str:
        return redact(Exception.__str__(self))


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    cache: str
    url: str


class HttpClient:
    def __init__(
        self,
        connector: str,
        *,
        policy: EgressPolicy,
        cache: HttpCache,
        limiter: RateLimiter,
        timeout: float = 30,
        retries: int = 3,
        user_agent: str,
        rate: float = 1.0,
        burst: int = 5,
        window: str = "rolling",
        auth_scope: str = "anonymous",
        offline: bool = False,
        transport=None,
        sleeper=None,
        rng=None,
        max_bytes: int = 50 * 1024 * 1024,
        max_retry_wait: float | None = None,
    ):
        self.connector = connector
        self.policy = policy
        self.cache = cache
        self.limiter = limiter
        self.timeout = timeout
        self.retries = retries
        self.user_agent = user_agent
        self.rate = rate
        self.burst = burst
        self.window = window
        self.auth_scope = auth_scope
        self.offline = offline
        self._sleep = sleeper or __import__("time").sleep
        self._rng = rng or random.random
        self.max_bytes = max_bytes
        self.max_retry_wait = max_retry_wait
        mounts = None
        if transport is None:
            # Direct connections go through the egress transport. Proxied
            # requests keep the environment proxy settings, and the proxy
            # resolves the name.
            transport = egress_transport(policy)
            mounts = _proxy_mounts()
        self._client = httpx.Client(
            transport=transport,
            mounts=mounts,
            follow_redirects=False,
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def get(
        self,
        url: str,
        *,
        params=None,
        headers=None,
        ttl: int,
        stale_if_error: int = 86400,
        skip_cache: bool = False,
    ) -> Response:
        return self._fetch(
            "GET",
            url,
            params=params,
            headers=headers,
            content=None,
            ttl=ttl,
            stale_if_error=stale_if_error,
            skip_cache=skip_cache,
        )

    def post_json(
        self,
        url: str,
        body: dict,
        *,
        headers=None,
        ttl: int,
        cache_key_extra: str = "",
        stale_if_error: int = 86400,
        skip_cache: bool = False,
    ) -> Response:
        encoded = _json_bytes(body)
        key_body = encoded + b"\n" + cache_key_extra.encode()
        extra_headers = {"content-type": "application/json"}
        return self._fetch(
            "POST",
            url,
            params=None,
            headers={**extra_headers, **(headers or {})},
            content=encoded,
            ttl=ttl,
            stale_if_error=stale_if_error,
            key_body=key_body,
            skip_cache=skip_cache,
        )

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers=None,
        ttl: int,
        stale_if_error: int = 86400,
        skip_cache: bool = False,
    ) -> Response:
        encoded = urlencode(sorted(fields.items())).encode()
        extra_headers = {"content-type": "application/x-www-form-urlencoded"}
        return self._fetch(
            "POST",
            url,
            params=None,
            headers={**extra_headers, **(headers or {})},
            content=encoded,
            ttl=ttl,
            stale_if_error=stale_if_error,
            key_body=encoded,
            skip_cache=skip_cache,
        )

    def _fetch(
        self,
        method: str,
        url: str,
        *,
        params,
        headers,
        content: bytes | None,
        ttl: int,
        stale_if_error: int,
        key_body: bytes | None = None,
        skip_cache: bool = False,
    ) -> Response:
        # Host list only. A cache answer sends nothing, so it needs no DNS.
        # Every network hop is checked again in _request.
        self.policy.check(url, resolve=False)
        key_material = key_body if key_body is not None else (content or b"")
        cache_key = self.cache.key(method, url, params, key_material, self.auth_scope)
        cached = None if skip_cache else self.cache.get(cache_key)
        if not skip_cache and (self.offline or (cached and self.cache.fresh(cached))):
            if cached is None:
                raise HttpError(redact(f"offline and no cache for {url}"))
            state = "hit" if self.cache.fresh(cached) else "stale"
            return _from_cache(cached, state, url)
        outbound = dict(headers or {})
        outbound.setdefault("user-agent", self.user_agent)
        outbound.setdefault("accept", "application/json, application/xml, text/xml, */*")
        if cached and cached.etag:
            outbound["if-none-match"] = cached.etag
        if cached and cached.last_modified:
            outbound["if-modified-since"] = cached.last_modified
        try:
            status, response_headers, body, final_url = self._request(
                method, url, params=params, headers=outbound, content=content
            )
        except (HttpError, EgressUnresolved, httpx.HTTPError) as exc:
            if cached and self.cache.within_stale(cached, stale_if_error):
                return _from_cache(cached, "stale", url)
            raise HttpError(redact(str(exc))) from None
        if status == 304:
            if cached is None:
                raise HttpError("not modified without a cache entry")
            self.cache.touch(cache_key)
            return _from_cache(cached, "hit", final_url)
        stored_headers = {key.lower(): value for key, value in response_headers.items()}
        if status >= 500:
            if cached and self.cache.within_stale(cached, stale_if_error):
                return _from_cache(cached, "stale", final_url)
            raise HttpError(f"upstream status {status}")
        if 200 <= status < 300:
            self.cache.put(cache_key, status=status, headers=stored_headers, body=body, ttl=ttl)
        return Response(
            status=status,
            headers=redact_headers(stored_headers),
            body=body,
            cache="miss",
            url=final_url,
        )

    def _request(self, method: str, url: str, *, params, headers: dict, content: bytes | None):
        attempt = 0
        redirects = 0
        current = url
        current_method = method
        current_content = content
        while True:
            # Host list for this hop. A direct connection resolves once and
            # vets the address it connects to (see egress_transport). A proxy
            # resolves the name itself.
            self.policy.check(current, resolve=False)
            host = httpx.URL(current).host or ""
            self.limiter.acquire(
                f"{self.connector}:{host}",
                rate=self.rate,
                burst=self.burst,
                window=self.window,
            )
            try:
                response = self._client.request(
                    current_method,
                    current,
                    params=params if current == url else None,
                    headers=headers,
                    content=current_content,
                )
            except httpx.HTTPError as exc:
                if attempt >= self.retries:
                    raise HttpError(redact(str(exc))) from None
                self._sleep(self._backoff(attempt))
                attempt += 1
                continue
            if response.status_code in (429, 503) and attempt < self.retries:
                delay = self._retry_delay(response, attempt)
                # A Retry-After longer than max_retry_wait is returned, not slept through,
                # so the caller can stay inside its own tool timeout.
                if self.max_retry_wait is None or delay <= self.max_retry_wait:
                    self._sleep(min(60.0, delay))
                    attempt += 1
                    response.close()
                    continue
            if response.status_code in _REDIRECTS and redirects < 5:
                location = response.headers.get("location")
                response.close()
                if not location:
                    raise HttpError("redirect with no location")
                current = str(httpx.URL(current).join(location))
                redirects += 1
                if response.status_code in (301, 302, 303):
                    current_method = "GET"
                    current_content = None
                headers = _drop_secret_headers(headers)
                continue
            body = _read_capped(response, self.max_bytes)
            kept = {key: value for key, value in response.headers.items()}
            final = str(response.url)
            response.close()
            return response.status_code, kept, body, final

    def _backoff(self, attempt: int) -> float:
        ceiling = min(60.0, 1.0 * (2**attempt))
        return self._rng() * ceiling

    def _retry_delay(self, response: httpx.Response, attempt: int) -> float:
        header = response.headers.get("retry-after")
        wait = _retry_after_seconds(header) if header else None
        if wait is None:
            return self._backoff(attempt)
        if self.max_retry_wait is None:
            return min(60.0, wait)
        return wait


class _EgressBackend(httpcore.NetworkBackend):
    """Resolves through the policy and connects only to an address that passed."""

    def __init__(self, policy: EgressPolicy, inner: httpcore.NetworkBackend | None = None):
        self._policy = policy
        self._inner = inner or httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ) -> httpcore.NetworkStream:
        failure: Exception | None = None
        for address in self._policy.connect_addresses(host):
            try:
                # A numeric host needs no second lookup. TLS still uses the
                # name from the URL for SNI and certificate checks.
                return self._inner.connect_tcp(
                    address.compressed,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                failure = exc
        raise failure or httpcore.ConnectError(f"no address for {host}")

    def connect_unix_socket(self, path: str, timeout=None, socket_options=None):
        raise httpcore.ConnectError("unix sockets are not allowed")

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


class _EgressTransport(httpx.HTTPTransport):
    # handle_request is inherited, so cassette players that patch
    # HTTPTransport still apply to this class.
    def __init__(self, policy: EgressPolicy, network_backend=None):
        self._pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(),
            max_connections=100,
            max_keepalive_connections=20,
            keepalive_expiry=5.0,
            network_backend=_EgressBackend(policy, network_backend),
        )


def egress_transport(policy: EgressPolicy, *, network_backend=None) -> httpx.HTTPTransport:
    """An httpx transport whose direct connections are vetted by ``policy``.

    ``network_backend`` replaces the socket layer, for tests.
    """
    return _EgressTransport(policy, network_backend)


def _proxy_mounts() -> dict[str, httpx.HTTPTransport | None]:
    # Same rules httpx applies on its own (HTTPS_PROXY, ALL_PROXY, NO_PROXY).
    # None sends that pattern to the egress transport.
    return {
        pattern: None if proxy is None else httpx.HTTPTransport(proxy=proxy)
        for pattern, proxy in get_environment_proxies().items()
    }


def _retry_after_seconds(header: str) -> float | None:
    """Seconds from a Retry-After value (delay or HTTP date), never negative."""
    text = header.strip()
    try:
        seconds = float(text)
    except ValueError:
        try:
            parsed = email.utils.parsedate_to_datetime(text)
        except (TypeError, ValueError):
            return None
        if parsed is None:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.UTC)
        seconds = (parsed - datetime.datetime.now(datetime.UTC)).total_seconds()
    if not math.isfinite(seconds):
        return None
    return max(0.0, seconds)


def _json_bytes(body: dict) -> bytes:
    import json

    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode()


def _from_cache(item, state: str, url: str) -> Response:
    return Response(
        status=item.status,
        headers=redact_headers(item.headers),
        body=item.body,
        cache=state,
        url=url,
    )


def _drop_secret_headers(headers: dict) -> dict:
    return {key: value for key, value in headers.items() if key.lower() not in SECRET_HEADER_NAMES}


def _read_capped(response: httpx.Response, max_bytes: int) -> bytes:
    buf = bytearray()
    for chunk in response.iter_bytes():
        buf.extend(chunk)
        if len(buf) > max_bytes:
            response.close()
            raise HttpError("response exceeds size cap")
    return bytes(buf)
