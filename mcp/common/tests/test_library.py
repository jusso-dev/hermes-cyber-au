"""Offline tests for the shared connector library."""

from __future__ import annotations

import asyncio
import logging
import multiprocessing
import socket
import sys
import time
from pathlib import Path

import httpcore
import httpx
import pytest
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import FAKE_IP_ENV, EgressDenied, EgressPolicy, EgressUnresolved
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError, _EgressBackend, egress_transport
from cyberau_common.ratelimit import RateLimited, RateLimiter
from cyberau_common.secrets import RedactFilter, redact
from cyberau_common.server import Connector, ToolSpec, build_server
from hypothesis import given
from hypothesis import strategies as st

SECRET = "super-secret-value"


def _policy(tmp_path: Path, body: str, connector: str = "demo") -> EgressPolicy:
    path = tmp_path / "allow.yaml"
    path.write_text(body, encoding="utf-8")
    return EgressPolicy(path, connector, resolver=lambda host: [_ip("1.1.1.1")])


def _ip(text: str):
    import ipaddress

    return ipaddress.ip_address(text)


class _FakeBackend(httpcore.NetworkBackend):
    """Socket layer stand-in. Records the host it was asked to reach."""

    def __init__(self, status: int = 200, body: bytes = b"ok"):
        self.hosts: list[str] = []
        self._reply = f"HTTP/1.1 {status} OK\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.hosts.append(host)
        return httpcore.MockStream([self._reply])

    def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise AssertionError("unix socket")

    def sleep(self, seconds):
        return None


def _guarded_client(tmp_path: Path, policy: EgressPolicy, backend: _FakeBackend) -> HttpClient:
    """A client whose transport runs the connect-time check over a fake socket layer."""
    transport = egress_transport(policy, network_backend=backend)
    return _client(tmp_path, None, policy=policy, transport=transport)


def _client(tmp_path: Path, handler, **kwargs) -> HttpClient:
    policy = kwargs.pop(
        "policy",
        _policy(tmp_path, "connectors:\n  demo:\n    hosts: [example.com]\n"),
    )
    clock = kwargs.pop("clock", None)
    cache = HttpCache(tmp_path / "cache.sqlite", now=clock)
    limiter = kwargs.pop("limiter", None) or RateLimiter(tmp_path / "limit.sqlite")
    return HttpClient(
        "demo",
        policy=policy,
        cache=cache,
        limiter=limiter,
        user_agent=USER_AGENT,
        transport=kwargs.pop("transport", None) or httpx.MockTransport(handler),
        sleeper=kwargs.pop("sleeper", lambda _seconds: None),
        rng=kwargs.pop("rng", lambda: 0.0),
        rate=kwargs.pop("rate", 100.0),
        burst=kwargs.pop("burst", 10),
        window=kwargs.pop("window", "bucket"),
        **kwargs,
    )


class TestEgress:
    def test_allows_listed_host(self, tmp_path: Path):
        policy = _policy(tmp_path, "connectors:\n  demo:\n    hosts: [example.com]\n")
        policy.check("https://example.com/a")

    def test_denies_other_host(self, tmp_path: Path):
        policy = _policy(tmp_path, "connectors:\n  demo:\n    hosts: [example.com]\n")
        with pytest.raises(EgressDenied):
            policy.check("https://evil.test/a")

    def test_denies_userinfo_and_http_and_ip_literal(self, tmp_path: Path):
        policy = _policy(tmp_path, "connectors:\n  demo:\n    hosts: [example.com]\n")
        with pytest.raises(EgressDenied):
            policy.check("https://user:pass@example.com/a")
        with pytest.raises(EgressDenied):
            policy.check("http://example.com/a")
        with pytest.raises(EgressDenied):
            policy.check("https://1.1.1.1/a")

    def test_denies_private_dns_and_link_local(self, tmp_path: Path):
        path = tmp_path / "allow.yaml"
        path.write_text("connectors:\n  demo:\n    hosts: [example.com]\n", encoding="utf-8")
        private = EgressPolicy(path, "demo", resolver=lambda host: [_ip("10.0.0.1")])
        with pytest.raises(EgressDenied):
            private.check("https://example.com/")
        local = EgressPolicy(path, "demo", resolver=lambda host: [_ip("fe80::1")])
        with pytest.raises(EgressDenied):
            local.check("https://example.com/")

    @pytest.mark.parametrize(
        "address",
        [
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "2002:7f00:1::1",
            "64:ff9b::7f00:1",
            "::",
            "192.0.0.8",
            "198.18.0.1",
            "224.0.0.1",
            "fe80::1%eth0",
        ],
    )
    def test_denies_mapped_embedded_and_special_addresses(self, tmp_path: Path, address: str):
        path = tmp_path / "allow.yaml"
        path.write_text("connectors:\n  demo:\n    hosts: [example.com]\n", encoding="utf-8")
        policy = EgressPolicy(path, "demo", resolver=lambda host: [_ip(address)])
        with pytest.raises(EgressDenied):
            policy.check("https://example.com/")

    def test_punycode_lookalike_is_denied(self, tmp_path: Path):
        policy = _policy(tmp_path, "connectors:\n  demo:\n    hosts: [example.com]\n")
        lookalike = "ex" + "\u0430" + "mple.com"
        with pytest.raises(EgressDenied):
            policy.check(f"https://{lookalike}/")

    def test_http_loopback_when_opted_in(self, tmp_path: Path):
        path = tmp_path / "allow.yaml"
        path.write_text(
            "connectors:\n  demo:\n    hosts: []\n    allow_http_loopback: true\n",
            encoding="utf-8",
        )
        policy = EgressPolicy(path, "demo", resolver=lambda host: [_ip("127.0.0.1")])
        policy.check("http://localhost/health")
        with pytest.raises(EgressDenied):
            policy.check("http://example.com/")

    def test_more_denials(self, tmp_path: Path):
        policy = _policy(tmp_path, "connectors:\n  demo:\n    hosts: [example.com]\n")
        with pytest.raises(EgressDenied):
            policy.check("ftp://example.com/a")
        with pytest.raises(EgressDenied):
            policy.check("https://")
        empty = EgressPolicy(tmp_path / "missing.yaml", "demo", resolver=lambda host: [])
        with pytest.raises(EgressDenied):
            empty.check("https://example.com/")
        unresolved = tmp_path / "unresolved.yaml"
        unresolved.write_text("connectors:\n  demo:\n    hosts: [example.com]\n", encoding="utf-8")
        with pytest.raises(EgressDenied):
            EgressPolicy(unresolved, "demo", resolver=lambda host: []).check("https://example.com/")
        path = tmp_path / "bad.yaml"
        path.write_text("connectors: []\n", encoding="utf-8")
        with pytest.raises(EgressDenied):
            EgressPolicy(path, "demo")
        path.write_text(
            "connectors:\n  demo:\n    hosts: ['1.1.1.1']\n    allow_ip_literals: true\n",
            encoding="utf-8",
        )
        allowed = EgressPolicy(path, "demo")
        allowed.check("https://1.1.1.1/x")
        with pytest.raises(EgressDenied):
            _policy(tmp_path, "connectors:\n  demo:\n    hosts: ['bad host']\n").check(
                "https://bad host/"
            )

    def test_scoped_and_mapped_addresses_are_refused(self, tmp_path: Path):
        path = tmp_path / "allow.yaml"
        path.write_text("connectors:\n  demo:\n    hosts: [example.com]\n", encoding="utf-8")
        for address in (
            "100.64.0.1",
            "169.254.169.254",
            "224.0.0.1",
            "::",
            "fec0::1",
            "ff02::1",
            "fe80::1%eth0",
            "::ffff:10.0.0.1",
            "::ffff:1.1.1.1",
        ):
            policy = EgressPolicy(
                path, "demo", resolver=lambda host, address=address: [_ip(address)]
            )
            with pytest.raises(EgressDenied):
                policy.check("https://example.com/")

    def test_yaml_cannot_drop_the_floor(self, tmp_path: Path):
        path = tmp_path / "allow.yaml"
        path.write_text(
            "version: 1\n"
            "global_deny_cidrs: [192.0.2.0/24]\n"
            "connectors:\n  demo:\n    hosts: [example.com]\n",
            encoding="utf-8",
        )
        policy = EgressPolicy(path, "demo", resolver=lambda host: [_ip("100.64.0.1")])
        with pytest.raises(EgressDenied):
            policy.check("https://example.com/")
        extra = EgressPolicy(path, "demo", resolver=lambda host: [_ip("1.2.3.4")])
        extra_path = tmp_path / "extra.yaml"
        extra_path.write_text(
            "version: 1\nglobal_deny_cidrs: [1.2.3.0/24]\nconnectors:\n  demo: [example.com]\n",
            encoding="utf-8",
        )
        listed = EgressPolicy(extra_path, "demo", resolver=lambda host: [_ip("1.2.3.4")])
        with pytest.raises(EgressDenied):
            listed.check("https://example.com/")
        EgressPolicy(extra_path, "demo", resolver=lambda host: [_ip("1.1.1.1")]).check(
            "https://example.com/"
        )
        assert extra.hosts == {"example.com"}

    def test_scoped_literal_is_refused_when_listed(self, tmp_path: Path):
        path = tmp_path / "allow.yaml"
        path.write_text(
            "connectors:\n  demo:\n    hosts: ['fe80::1%eth0', example.com]\n"
            "    allow_ip_literals: true\n",
            encoding="utf-8",
        )
        policy = EgressPolicy(path, "demo", resolver=lambda host: [_ip("1.1.1.1")])
        with pytest.raises(EgressDenied, match="blocked"):
            policy.check("https://[fe80::1%25eth0]/")

    def test_loopback_opt_in_does_not_cover_https_or_listed_names(self, tmp_path: Path):
        path = tmp_path / "allow.yaml"
        path.write_text(
            "connectors:\n  demo:\n    hosts: [example.com, localhost]\n"
            "    allow_http_loopback: true\n",
            encoding="utf-8",
        )
        policy = EgressPolicy(path, "demo", resolver=lambda host: [_ip("127.0.0.1")])
        with pytest.raises(EgressDenied, match="blocked"):
            policy.check("https://example.com/")
        with pytest.raises(EgressDenied, match="blocked"):
            policy.check("https://localhost/")
        policy.check("http://localhost/")

    def test_dns_failure_is_a_typed_refusal(self, tmp_path: Path, monkeypatch):
        path = tmp_path / "allow.yaml"
        path.write_text("connectors:\n  demo:\n    hosts: [example.com]\n", encoding="utf-8")

        def failing(*_args, **_kwargs):
            raise socket.gaierror(-2, "Name or service not known")

        monkeypatch.setattr(socket, "getaddrinfo", failing)
        with pytest.raises(EgressUnresolved):
            EgressPolicy(path, "demo").check("https://example.com/")

    def test_host_only_check_does_not_resolve(self, tmp_path: Path):
        def resolver(host):
            raise AssertionError("resolved")

        path = tmp_path / "allow.yaml"
        path.write_text("connectors:\n  demo:\n    hosts: [example.com]\n", encoding="utf-8")
        policy = EgressPolicy(path, "demo", resolver=resolver)
        policy.check("https://example.com/", resolve=False)
        with pytest.raises(EgressDenied):
            policy.check("https://evil.test/", resolve=False)


class TestConnectTimeEgress:
    """The address vetted at connect time is the address the socket layer gets."""

    ALLOW = "connectors:\n  demo:\n    hosts: [example.com]\n"

    def _policy(self, tmp_path: Path, *answers: str) -> EgressPolicy:
        path = tmp_path / "allow.yaml"
        path.write_text(self.ALLOW, encoding="utf-8")
        queue = [[_ip(item)] for item in answers]
        return EgressPolicy(path, "demo", resolver=lambda host: queue.pop(0))

    def test_connects_to_the_vetted_address(self, tmp_path: Path):
        backend = _FakeBackend()
        client = _guarded_client(tmp_path, self._policy(tmp_path, "1.1.1.1"), backend)
        assert client.get("https://example.com/a", ttl=5).body == b"ok"
        assert backend.hosts == ["1.1.1.1"]
        client.close()

    def test_public_at_check_time_private_at_connect_time_is_refused(self, tmp_path: Path):
        policy = self._policy(tmp_path, "1.1.1.1", "10.0.0.1")
        policy.check("https://example.com/a")
        backend = _FakeBackend()
        client = _guarded_client(tmp_path, policy, backend)
        with pytest.raises(EgressDenied, match="blocked"):
            client.get("https://example.com/a", ttl=5)
        assert backend.hosts == []
        client.close()

    def test_mixed_answer_is_refused(self, tmp_path: Path):
        path = tmp_path / "allow.yaml"
        path.write_text(self.ALLOW, encoding="utf-8")
        policy = EgressPolicy(path, "demo", resolver=lambda host: [_ip("1.1.1.1"), _ip("::1")])
        backend = _FakeBackend()
        client = _guarded_client(tmp_path, policy, backend)
        with pytest.raises(EgressDenied):
            client.get("https://example.com/a", ttl=5)
        assert backend.hosts == []
        client.close()

    def test_no_answer_at_connect_time_fails_closed(self, tmp_path: Path):
        path = tmp_path / "allow.yaml"
        path.write_text(self.ALLOW, encoding="utf-8")
        policy = EgressPolicy(path, "demo", resolver=lambda host: [])
        backend = _FakeBackend()
        client = _guarded_client(tmp_path, policy, backend)
        with pytest.raises(HttpError, match="did not resolve"):
            client.get("https://example.com/a", ttl=5)
        assert backend.hosts == []
        client.close()

    def test_next_address_is_tried_after_a_connect_error(self, tmp_path: Path):
        class Flaky(_FakeBackend):
            def connect_tcp(self, host, port, **kwargs):
                if host == "1.1.1.1":
                    self.hosts.append(host)
                    raise httpcore.ConnectError("refused")
                return super().connect_tcp(host, port, **kwargs)

        path = tmp_path / "allow.yaml"
        path.write_text(self.ALLOW, encoding="utf-8")
        policy = EgressPolicy(path, "demo", resolver=lambda host: [_ip("1.1.1.1"), _ip("8.8.8.8")])
        backend = Flaky()
        client = _guarded_client(tmp_path, policy, backend)
        assert client.get("https://example.com/a", ttl=5).body == b"ok"
        assert backend.hosts == ["1.1.1.1", "8.8.8.8"]
        client.close()

    def test_fake_ip_range_needs_the_opt_in(self, tmp_path: Path, monkeypatch):
        monkeypatch.delenv(FAKE_IP_ENV, raising=False)
        backend = _FakeBackend()
        client = _guarded_client(tmp_path, self._policy(tmp_path, "198.18.0.1"), backend)
        with pytest.raises(EgressDenied, match="blocked"):
            client.get("https://example.com/a", ttl=5)
        client.close()
        monkeypatch.setenv(FAKE_IP_ENV, "1")
        client = _guarded_client(tmp_path, self._policy(tmp_path, "198.18.0.1"), backend)
        assert client.get("https://example.com/b", ttl=5).body == b"ok"
        assert backend.hosts == ["198.18.0.1"]
        client.close()
        client = _guarded_client(tmp_path, self._policy(tmp_path, "10.0.0.1"), backend)
        with pytest.raises(EgressDenied, match="blocked"):
            client.get("https://example.com/c", ttl=5)
        client.close()

    def test_fake_ip_opt_in_does_not_cover_literals(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv(FAKE_IP_ENV, "1")
        path = tmp_path / "allow.yaml"
        path.write_text(
            "connectors:\n  demo:\n    hosts: [198.18.0.1]\n    allow_ip_literals: true\n",
            encoding="utf-8",
        )
        with pytest.raises(EgressDenied, match="blocked"):
            EgressPolicy(path, "demo").check("https://198.18.0.1/", resolve=False)

    def test_proxy_requests_do_not_resolve_locally(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
        monkeypatch.setenv("NO_PROXY", "direct.example")

        def resolver(host):
            raise AssertionError("resolved locally")

        path = tmp_path / "allow.yaml"
        path.write_text(
            "connectors:\n  demo:\n    hosts: [example.com, direct.example]\n",
            encoding="utf-8",
        )
        policy = EgressPolicy(path, "demo", resolver=resolver)
        client = HttpClient(
            "demo",
            policy=policy,
            cache=HttpCache(tmp_path / "cache.sqlite"),
            limiter=RateLimiter(tmp_path / "limit.sqlite"),
            user_agent=USER_AGENT,
        )
        proxied = client._client._transport_for_url(httpx.URL("https://example.com/a"))
        assert isinstance(proxied._pool, httpcore.HTTPProxy)
        direct = client._client._transport_for_url(httpx.URL("https://direct.example/a"))
        assert isinstance(direct._pool._network_backend, _EgressBackend)
        policy.check("https://example.com/a", resolve=False)
        client.close()

    def test_direct_requests_use_the_egress_transport(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr("cyberau_common.http.get_environment_proxies", dict)
        client = HttpClient(
            "demo",
            policy=_policy(tmp_path, self.ALLOW),
            cache=HttpCache(tmp_path / "cache.sqlite"),
            limiter=RateLimiter(tmp_path / "limit.sqlite"),
            user_agent=USER_AGENT,
        )
        transport = client._client._transport_for_url(httpx.URL("https://example.com/a"))
        assert isinstance(transport._pool._network_backend, _EgressBackend)
        client.close()


class TestCache:
    def test_hit_and_conditional_round_trip(self, tmp_path: Path):
        now = {"t": 1000.0}
        cache = HttpCache(tmp_path / "c.sqlite", now=lambda: now["t"])
        key = cache.key("GET", "https://example.com", {"q": "1"}, b"", "anonymous")
        cache.put(
            key,
            status=200,
            headers={"etag": "abc", "content-type": "text/plain"},
            body=b"hi",
            ttl=30,
        )
        item = cache.get(key)
        assert item is not None and cache.fresh(item) and item.body == b"hi"
        now["t"] = 1040
        assert not cache.fresh(item)
        assert cache.within_stale(cache.get(key), 86400)
        cache.touch(key)
        assert cache.fresh(cache.get(key))

    def test_key_ignores_secret_and_changes_with_scope(self, tmp_path: Path):
        cache = HttpCache(tmp_path / "c.sqlite")
        one = cache.key("GET", "https://example.com", None, b"", "anonymous")
        two = cache.key("GET", "https://example.com", None, b"", "nvd")
        assert one != two
        assert SECRET not in one


class TestLimiter:
    def test_rolling_window_maths(self, tmp_path: Path):
        clock = {"t": 0.0}
        limiter = RateLimiter(
            tmp_path / "r.sqlite", clock=lambda: clock["t"], sleeper=lambda _s: None
        )
        limiter.acquire("nvd", rate=2, burst=2, window="rolling", timeout=0)
        limiter.acquire("nvd", rate=2, burst=2, window="rolling", timeout=0)
        with pytest.raises(RateLimited):
            limiter.acquire("nvd", rate=2, burst=2, window="rolling", timeout=0)
        clock["t"] = 1.1
        limiter.acquire("nvd", rate=2, burst=2, window="rolling", timeout=0)

    def test_two_processes_share_a_bucket(self, tmp_path: Path):
        path = tmp_path / "shared.sqlite"
        limiter = RateLimiter(path)
        limiter.acquire("shared", rate=0.001, burst=1, window="rolling", timeout=0)
        ctx = multiprocessing.get_context("fork")
        with ctx.Pool(1) as pool:
            result = pool.apply(_child_acquire, (str(path), "shared"))
        assert result == "limited"

    def test_bucket_refills(self, tmp_path: Path):
        clock = {"t": 10.0}
        limiter = RateLimiter(tmp_path / "b.sqlite", clock=lambda: clock["t"])
        limiter.acquire("k", rate=1, burst=1, window="bucket", timeout=0)
        with pytest.raises(RateLimited):
            limiter.acquire("k", rate=1, burst=1, window="bucket", timeout=0)
        clock["t"] = 12
        limiter.acquire("k", rate=1, burst=1, window="bucket", timeout=0)

    def test_rejects_bad_arguments(self, tmp_path: Path):
        limiter = RateLimiter(tmp_path / "b.sqlite")
        with pytest.raises(ValueError):
            limiter.acquire("k", rate=0, burst=1)
        with pytest.raises(ValueError):
            limiter.acquire("k", rate=1, burst=1, window="nope")


def _child_acquire(path: str, key: str) -> str:
    from pathlib import Path

    from cyberau_common.ratelimit import RateLimited, RateLimiter

    limiter = RateLimiter(Path(path))
    try:
        limiter.acquire(key, rate=0.001, burst=1, window="rolling", timeout=0)
    except RateLimited:
        return "limited"
    return "ok"


class TestHttp:
    def test_cache_hit_skips_second_request(self, tmp_path: Path):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(200, content=b"body", headers={"etag": "v1"})

        client = _client(tmp_path, handler)
        first = client.get("https://example.com/a", ttl=60)
        second = client.get("https://example.com/a", ttl=60)
        assert first.cache == "miss" and second.cache == "hit"
        assert second.body == b"body"
        assert calls["n"] == 1
        client.close()

    def test_conditional_304(self, tmp_path: Path):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(200, content=b"body", headers={"etag": "v1"})
            assert request.headers["if-none-match"] == "v1"
            return httpx.Response(304)

        clock = {"t": 100.0}
        client = _client(tmp_path, handler, clock=lambda: clock["t"])
        client.get("https://example.com/a", ttl=10)
        clock["t"] = 1000
        again = client.get("https://example.com/a", ttl=10)
        assert again.cache == "hit" and again.body == b"body"
        client.close()

    def test_stale_if_error(self, tmp_path: Path):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(200, content=b"kept")
            raise httpx.ConnectError("down")

        clock = {"t": 100.0}
        client = _client(tmp_path, handler, clock=lambda: clock["t"], retries=0)
        client.get("https://example.com/a", ttl=10, stale_if_error=1000)
        clock["t"] = 130
        stale = client.get("https://example.com/a", ttl=10, stale_if_error=1000)
        assert stale.cache == "stale" and stale.body == b"kept"
        client.close()

    def test_retry_after_and_jitter(self, tmp_path: Path):
        delays: list[float] = []
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(429, headers={"retry-after": "0"})
            if calls["n"] == 2:
                return httpx.Response(503)
            return httpx.Response(200, content=b"ok")

        client = _client(tmp_path, handler, sleeper=delays.append, rng=lambda: 0.25)
        response = client.get("https://example.com/a", ttl=5)
        assert response.body == b"ok"
        assert 0.0 in delays
        assert any(item > 0 for item in delays)
        client.close()

    def test_retry_after_seconds_date_and_garbage(self, tmp_path: Path):
        import email.utils
        import time as _time

        soon = email.utils.formatdate(_time.time() + 30, usegmt=True)
        for header, check in (
            ("7", lambda d: d == 7.0),
            ("999", lambda d: d == 60.0),
            (soon, lambda d: 25.0 <= d <= 30.0),
            ("not a date", lambda d: 0.0 <= d <= 1.0),
        ):
            delays: list[float] = []
            calls = {"n": 0}

            def handler(request: httpx.Request, header=header) -> httpx.Response:
                calls["n"] += 1
                if calls["n"] == 1:
                    return httpx.Response(429, headers={"retry-after": header})
                return httpx.Response(200, content=b"ok")

            client = _client(tmp_path, handler, sleeper=delays.append, rng=lambda: 0.25)
            assert client.get(f"https://example.com/{len(header)}", ttl=5).body == b"ok"
            assert len(delays) == 1 and check(delays[0]), (header, delays)
            client.close()

    def test_redirect_to_denied_host(self, tmp_path: Path):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "example.com":
                return httpx.Response(302, headers={"location": "https://evil.test/x"})
            return httpx.Response(200, content=b"no")

        client = _client(tmp_path, handler)
        with pytest.raises(EgressDenied):
            client.get("https://example.com/a", ttl=5)
        client.close()

    def test_off_list_host_opens_no_socket(self, tmp_path: Path, monkeypatch):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(200, content=b"no")

        def opened(*_args, **_kwargs):
            raise AssertionError("socket opened")

        monkeypatch.setattr(socket, "getaddrinfo", opened)
        monkeypatch.setattr(socket, "create_connection", opened)
        client = _client(tmp_path, handler)
        with pytest.raises(EgressDenied):
            client.get("https://evil.test/a", ttl=5)
        assert calls["n"] == 0
        client.close()

    def test_redirect_to_private_literal_stops_before_the_next_request(self, tmp_path: Path):
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.host)
            return httpx.Response(302, headers={"location": "https://10.0.0.1/secret"})

        path = tmp_path / "allow.yaml"
        path.write_text(
            "connectors:\n  demo:\n    hosts: [example.com, 10.0.0.1]\n"
            "    allow_ip_literals: true\n",
            encoding="utf-8",
        )
        client = _client(
            tmp_path,
            handler,
            policy=EgressPolicy(path, "demo", resolver=lambda host: [_ip("1.1.1.1")]),
        )
        with pytest.raises(EgressDenied, match="blocked"):
            client.get("https://example.com/a", ttl=5)
        assert calls == ["example.com"]
        client.close()

    def _seeded_dns_down(self, tmp_path: Path, monkeypatch, clock, **kwargs):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"cached")

        _client(tmp_path, handler, clock=lambda: clock["t"]).get("https://example.com/a", ttl=5)

        def failing(*_args, **_kwargs):
            raise socket.gaierror(-2, "Name or service not known")

        monkeypatch.setattr(socket, "getaddrinfo", failing)
        path = tmp_path / "real.yaml"
        path.write_text("connectors:\n  demo:\n    hosts: [example.com]\n", encoding="utf-8")
        policy = EgressPolicy(path, "demo")
        backend = _FakeBackend()
        client = _client(
            tmp_path,
            handler,
            clock=lambda: clock["t"],
            policy=policy,
            transport=egress_transport(policy, network_backend=backend),
            **kwargs,
        )
        return client, backend

    def test_offline_cache_answer_needs_no_dns(self, tmp_path: Path, monkeypatch):
        clock = {"t": 0.0}
        client, _backend = self._seeded_dns_down(tmp_path, monkeypatch, clock, offline=True)
        clock["t"] = 100.0
        response = client.get("https://example.com/a", ttl=5)
        assert (response.cache, response.body) == ("stale", b"cached")
        with pytest.raises(EgressDenied):
            client.get("https://evil.test/a", ttl=5)
        client.close()

    def test_dns_failure_serves_stale_or_fails_as_http_error(self, tmp_path: Path, monkeypatch):
        clock = {"t": 0.0}
        client, backend = self._seeded_dns_down(tmp_path, monkeypatch, clock)
        clock["t"] = 100.0
        assert client.get("https://example.com/a", ttl=5).cache == "stale"
        with pytest.raises(HttpError):
            client.get("https://example.com/other", ttl=5)
        assert backend.hosts == []
        client.close()

    def test_secrets_are_redacted_in_errors(self, tmp_path: Path):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(f"Authorization: Bearer {SECRET} ?apiKey={SECRET}")

        client = _client(tmp_path, handler, retries=0)
        with pytest.raises(HttpError) as caught:
            client.get(
                "https://example.com/a", headers={"authorization": f"Bearer {SECRET}"}, ttl=5
            )
        assert SECRET not in str(caught.value)
        client.close()

    def test_size_cap(self, tmp_path: Path):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"x" * 50)

        client = _client(tmp_path, handler, max_bytes=10, retries=0)
        with pytest.raises(HttpError):
            client.get("https://example.com/a", ttl=5)
        client.close()

    def test_offline_without_cache(self, tmp_path: Path):
        client = _client(tmp_path, lambda request: httpx.Response(200), offline=True)
        with pytest.raises(HttpError):
            client.get("https://example.com/a", ttl=5)
        client.close()

    def test_post_json(self, tmp_path: Path):
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "POST"
            return httpx.Response(200, content=b'{"ok":true}')

        client = _client(tmp_path, handler)
        response = client.post_json(
            "https://example.com/a", {"q": 1}, ttl=5, cache_key_extra="scope"
        )
        assert response.cache == "miss"
        client.close()

    def test_post_form_and_skip_cache(self, tmp_path: Path):
        seen = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append((request.headers["content-type"], request.content))
            return httpx.Response(200, content=b'{"ok":true}')

        client = _client(tmp_path, handler)
        url = "https://example.com/a"
        first = client.post_form(url, {"url": "http://a.test/x?y=1", "q": "b"}, ttl=60)
        again = client.post_form(url, {"q": "b", "url": "http://a.test/x?y=1"}, ttl=60)
        fresh = client.post_form(
            url, {"q": "b", "url": "http://a.test/x?y=1"}, ttl=60, skip_cache=True
        )
        assert [first.cache, again.cache, fresh.cache] == ["miss", "hit", "miss"]
        assert len(seen) == 2
        assert seen[0][0] == "application/x-www-form-urlencoded"
        assert seen[0][1] == b"q=b&url=http%3A%2F%2Fa.test%2Fx%3Fy%3D1"
        client.close()

    def test_post_json_skip_cache_bypasses_a_fresh_entry(self, tmp_path: Path):
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(200, content=b'{"ok":true}')

        client = _client(tmp_path, handler)
        assert client.post_json("https://example.com/a", {"q": 1}, ttl=60).cache == "miss"
        assert client.post_json("https://example.com/a", {"q": 1}, ttl=60).cache == "hit"
        assert len(calls) == 1
        live = client.post_json("https://example.com/a", {"q": 1}, ttl=60, skip_cache=True)
        assert live.cache == "miss"
        assert len(calls) == 2
        client.close()

    def test_upstream_errors_and_bare_redirect(self, tmp_path: Path):
        def five_hundred(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        client = _client(tmp_path, five_hundred, retries=0)
        with pytest.raises(HttpError):
            client.get("https://example.com/a", ttl=5)
        client.close()

        def not_modified(request: httpx.Request) -> httpx.Response:
            return httpx.Response(304)

        client = _client(tmp_path, not_modified, retries=0)
        with pytest.raises(HttpError):
            client.get("https://example.com/a", ttl=5)
        client.close()

        def bare(request: httpx.Request) -> httpx.Response:
            return httpx.Response(302)

        client = _client(tmp_path, bare, retries=0)
        with pytest.raises(HttpError):
            client.get("https://example.com/a", ttl=5)
        client.close()

        def modified(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=b"a",
                headers={"last-modified": "Wed, 21 Oct 2015 07:28:00 GMT"},
            )

        client = _client(tmp_path, modified)
        assert client.get("https://example.com/a", ttl=30).body == b"a"
        client.close()


class TestEnvelope:
    def test_warning_redaction_and_cache_names(self):
        item = envelope(
            "demo",
            {"ok": True},
            urls=["https://example.com"],
            cache="miss",
            warnings=(f"Auth-Key: {SECRET}",),
        )
        assert item["untrusted"] is True
        assert SECRET not in item["warnings"][0]
        with pytest.raises(ValueError):
            envelope("demo", {}, cache="nope")

    def test_redact_headers_and_log(self):
        assert SECRET not in redact(
            f"Authorization: Bearer {SECRET} ?apiKey={SECRET} X-OTX-API-KEY: {SECRET}"
        )
        stream_text: list[str] = []

        class _Buf:
            def write(self, text: str) -> None:
                stream_text.append(text)

            def flush(self) -> None:
                return None

        handler = logging.StreamHandler(_Buf())
        handler.addFilter(RedactFilter())
        logger = logging.getLogger("cyberau-test-redact")
        logger.handlers = [handler]
        logger.setLevel(logging.INFO)
        logger.info("Auth-Key: %s", SECRET)
        assert SECRET not in "".join(stream_text)
        from cyberau_common.secrets import lookup, redact_headers

        assert lookup("CYBERAU_TEST_ABSENT_KEY") is None
        cleaned = redact_headers({"Authorization": SECRET, "Accept": "text/plain"})
        assert cleaned["Authorization"] == "[REDACTED]"
        assert untrusted_text("abcdef", "asd", max_len=3).startswith("<<untrusted source=asd>> abc")

    def test_fixtures_have_no_secret(self):
        for path in (Path(__file__).parent / "fixtures").rglob("*"):
            if path.is_file():
                assert SECRET not in path.read_text(encoding="utf-8")

    @given(st.text(max_size=200))
    def test_untrusted_text_property(self, value: str):
        wrapped = untrusted_text(value, "asd", max_len=40)
        assert wrapped.startswith("<<untrusted source=asd>> ")
        assert wrapped.endswith(" <<end untrusted>>")
        inner = wrapped.removeprefix("<<untrusted source=asd>> ").removesuffix(" <<end untrusted>>")
        assert len(inner) <= 40
        assert "\u202e" not in wrapped
        assert all(ord(char) >= 32 or char == " " for char in inner)


class TestServer:
    def test_read_only_hint_unless_writes(self):
        connector = Connector(
            key="demo",
            server_name="demo",
            attribution="demo",
            tools=[
                ToolSpec("demo_read", "Read.", lambda: {"ok": True}),
                ToolSpec("demo_write", "Write.", lambda: {"ok": True}, writes=True),
            ],
        )
        server = build_server(connector)
        tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
        assert tools["demo_read"].annotations.read_only_hint is True
        assert tools["demo_write"].annotations.read_only_hint is False

    def test_stdio_lists_tools_quickly(self):
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        # The dev environment carries rfc3987-syntax (via stix2-validator and
        # cyclonedx), and jsonschema builds its Lark grammar on import, which costs
        # about half a second. The shipped runtime set (tools/release/sbom.py) does
        # not include it, so hide it to time what users actually start.
        launch = (
            "import sys; sys.modules['rfc3987_syntax'] = None; "
            "from cyberau_common.cli import main; "
            "raise SystemExit(main(['serve', 'stub']))"
        )

        async def run():
            params = StdioServerParameters(command=sys.executable, args=["-c", launch])
            started = time.perf_counter()
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listed = await session.list_tools()
            return time.perf_counter() - started, listed

        # The first start in a fresh CI venv compiles bytecode for the whole MCP
        # stack. Hermes starts servers after install, so time a warm start.
        asyncio.run(run())
        elapsed, listed = asyncio.run(run())
        assert elapsed < 1.5
        assert listed.tools[0].name == "stub_ping"
        assert listed.tools[0].annotations.read_only_hint is True

    def test_wrapper_returns_errors_as_envelopes(self):
        def boom() -> dict:
            raise RuntimeError("Auth-Key: super-secret-value")

        def passthrough() -> dict:
            return envelope("demo", {"ok": True}, cache="snapshot")

        connector = Connector(
            key="demo",
            server_name="demo",
            attribution="demo",
            tools=[
                ToolSpec("demo_boom", "Boom.", boom),
                ToolSpec("demo_pass", "Pass.", passthrough),
            ],
        )
        server = build_server(connector)

        async def run():
            failed = await server.call_tool("demo_boom", {})
            passed = await server.call_tool("demo_pass", {})
            ping = await build_server(
                __import__("cyberau_common.stub", fromlist=["connector"]).connector()
            ).call_tool("stub_ping", {"echo": "hi"})
            return failed, passed, ping

        failed, passed, ping = asyncio.run(run())
        assert SECRET not in str(failed)
        assert passed is not None and ping is not None


class TestCli:
    def test_health_and_placeholders(self, capsys):
        from cyberau_common.cli import main

        assert main(["health", "stub", "--offline"]) == 0
        assert "ok" in capsys.readouterr().out
        assert main(["health", "missing"]) == 1
        assert main(["refresh"]) == 2  # --sources is required


class TestRetryAfterParsing:
    def test_seconds_dates_and_junk(self):
        from cyberau_common.http import _retry_after_seconds

        assert _retry_after_seconds("7") == 7.0
        assert _retry_after_seconds("-5") == 0.0
        assert _retry_after_seconds("inf") is None
        assert _retry_after_seconds("nonsense") is None
        assert _retry_after_seconds("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0
        assert _retry_after_seconds("Wed, 21 Oct 2099 07:28:00 GMT") > 3600

    def test_wait_ceiling_skips_a_longer_retry(self, tmp_path: Path):
        delays: list[float] = []
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(429, headers={"retry-after": "100"})

        client = _client(tmp_path, handler, sleeper=delays.append, max_retry_wait=10)
        assert client.get("https://example.com/a", ttl=5).status == 429
        assert calls["n"] == 1 and delays == []
        client.close()
