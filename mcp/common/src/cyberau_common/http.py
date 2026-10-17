"""HTTP client with egress checks, caching, rate limits, and bounded retries."""

from __future__ import annotations

import email.utils
import random
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressPolicy
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import redact, redact_headers

_REDIRECTS = {301, 302, 303, 307, 308}


class HttpError(Exception):
    """A request failed and no stale cache could answer."""


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
        self._client = httpx.Client(
            transport=transport,
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
        self.policy.check(url)
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
        except (HttpError, httpx.HTTPError) as exc:
            if cached and self.cache.within_stale(cached, stale_if_error):
                return _from_cache(cached, "stale", url)
            raise HttpError(redact(str(exc))) from exc
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
        if status < 400:
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
            self.policy.check(current)
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
                    raise HttpError(redact(str(exc))) from exc
                self._sleep(self._backoff(attempt))
                attempt += 1
                continue
            if response.status_code in (429, 503) and attempt < self.retries:
                self._sleep(self._retry_delay(response, attempt))
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
        if header:
            try:
                return min(60.0, float(header))
            except ValueError:
                parsed = email.utils.parsedate_to_datetime(header)
                if parsed is not None:
                    return min(60.0, 1.0)
        return self._backoff(attempt)


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
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in {"authorization", "auth-key", "x-otx-api-key", "x-api-key", "api-key"}
    }


def _read_capped(response: httpx.Response, max_bytes: int) -> bytes:
    buf = bytearray()
    for chunk in response.iter_bytes():
        buf.extend(chunk)
        if len(buf) > max_bytes:
            response.close()
            raise HttpError("response exceeds size cap")
    return bytes(buf)
