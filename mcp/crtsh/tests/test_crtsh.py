import asyncio
import json
import sqlite3
import time
from pathlib import Path

import cyberau_crtsh.source as source
import httpx
import jsonschema
import pytest
from cyberau_common.cache import HttpCache
from cyberau_common.server import build_server
from cyberau_crtsh.source import (
    ATTRIBUTION,
    connector,
    crtsh_certs,
    schema_drift,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
PACKAGE = Path(__file__).resolve().parents[1]
EXAMPLE = (FIXTURES / "crtsh_example.json").read_bytes()


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_CRTSH_SNAPSHOT", str(FIXTURES / "crtsh_example.json"))
    monkeypatch.setenv("CYBERAU_TODAY", "2026-10-17")
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    yield
    source._TRANSPORT = None
    source._SLEEP = time.sleep
    source._CLOCK = time.monotonic


def test_certs_are_deduped_and_untrusted():
    found = crtsh_certs("example.com")
    assert found["cache"] == "snapshot"
    assert found["attribution"] == ATTRIBUTION
    assert found["source"] == "crtsh"
    serials = [row["serial_number"] for row in found["data"]]
    assert serials == ["feedface", "abc123"]
    assert serials.count("abc123") == 1
    apex = found["data"][1]
    assert any("www.example.com" in name for name in apex["names"])
    assert "<<untrusted source=crtsh>>" in apex["issuer"]
    hostile = found["data"][0]
    wrapped = next(name for name in hostile["names"] if "ignore previous instructions" in name)
    assert wrapped.startswith("<<untrusted source=crtsh>>")
    assert wrapped.endswith("<<end untrusted>>")
    logged = (Path(isolated_data()) / "crtsh-observations.jsonl").read_text(encoding="utf-8")
    assert logged.count("abc123") == 1
    assert "feedface" in logged


def test_subdomains_expired_and_empty(monkeypatch):
    exact = crtsh_certs("example.com", include_subdomains=False)
    assert [row["serial_number"] for row in exact["data"]] == ["abc123"]
    kept = crtsh_certs("example.com", include_expired=True)
    assert "deadbeef" in [row["serial_number"] for row in kept["data"]]
    missing = crtsh_certs("other.example")
    assert missing["data"] == []
    assert missing["warnings"]
    monkeypatch.setenv("CYBERAU_CRTSH_SNAPSHOT", str(FIXTURES / "crtsh_empty.json"))
    empty = crtsh_certs("example.com")
    assert empty["data"] == []
    assert empty["warnings"]
    assert crtsh_certs("https://example.com")["warnings"]
    assert crtsh_certs("")["warnings"]


def test_malformed_payload_warns(monkeypatch):
    monkeypatch.setenv("CYBERAU_CRTSH_SNAPSHOT", str(FIXTURES / "crtsh_502.html"))
    warned = crtsh_certs("example.com")
    assert warned["data"] == []
    assert warned["warnings"]
    assert "not usable" in warned["warnings"][0]
    monkeypatch.setenv("CYBERAU_CRTSH_SNAPSHOT", str(FIXTURES / "crtsh_drift.json"))
    drifted = crtsh_certs("example.com")
    assert drifted["warnings"]
    assert "serial_number" in drifted["warnings"][0]
    assert schema_drift(json.loads((FIXTURES / "crtsh_drift.json").read_text(encoding="utf-8")))
    assert schema_drift([]) is None


def test_schema_probe_and_limits():
    tools = {tool.name: tool for tool in asyncio.run(build_server(connector()).list_tools())}
    spec = tools["crtsh_certs"]
    assert spec.annotations.readOnlyHint is True
    assert spec.annotations.openWorldHint is True
    assert spec.inputSchema["required"] == ["domain"]
    assert spec.inputSchema["properties"]["include_subdomains"]["default"] is True
    assert spec.inputSchema["properties"]["include_expired"]["default"] is False
    schema_path = PACKAGE / "schema" / "crtsh_certs.response.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    for row in crtsh_certs("example.com")["data"]:
        jsonschema.validate(row, schema)
    assert connector().health(live=False, check_schema=True).ok is True
    assert source.BURST == 1
    assert source.RATE <= 1 / 5
    assert source.TIMEOUT <= 90
    assert source.CACHE_TTL == 24 * 3600


def test_schema_drift_probe_fails(monkeypatch):
    monkeypatch.setenv("CYBERAU_CRTSH_SNAPSHOT", str(FIXTURES / "crtsh_drift.json"))
    probe = connector().health(live=False, check_schema=True)
    assert probe.ok is False
    assert "serial_number" in probe.detail


def test_query_retry_redirect_auth_and_timeout(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_CRTSH_SNAPSHOT")
    slept: list[float] = []
    state = {"t": 0.0}

    def clock() -> float:
        return state["t"]

    def sleeper(seconds: float) -> None:
        slept.append(float(seconds))
        state["t"] += float(seconds)

    source._CLOCK = clock
    source._SLEEP = sleeper
    seen: list[httpx.URL] = []

    def ok(request: httpx.Request) -> httpx.Response:
        seen.append(request.url)
        if len(seen) == 1:
            return httpx.Response(429, headers={"retry-after": "2"})
        return httpx.Response(200, content=EXAMPLE)

    source._TRANSPORT = httpx.MockTransport(ok)
    found = crtsh_certs("example.com")
    assert found["data"][0]["serial_number"] == "feedface"
    assert seen[0].params["q"] == "%.example.com"
    assert seen[0].params["exclude"] == "expired"
    assert 2.0 in slept

    def exact(request: httpx.Request) -> httpx.Response:
        assert request.url.params["q"] == "example.com"
        assert "exclude" not in request.url.params
        return httpx.Response(200, content=EXAMPLE)

    source._TRANSPORT = httpx.MockTransport(exact)
    current = crtsh_certs("Example.COM", include_subdomains=False, include_expired=True)
    assert [row["serial_number"] for row in current["data"]] == ["abc123"]

    def redirect(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.test/stolen"})

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "redirect"))
    source._TRANSPORT = httpx.MockTransport(redirect)
    refused = crtsh_certs("example.com")
    assert refused["warnings"]
    assert "evil.test" in refused["warnings"][0]

    def denied(status: int):
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(status, content=b"no")

        return handler

    for status in (401, 403):
        monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / f"auth-{status}"))
        source._TRANSPORT = httpx.MockTransport(denied(status))
        blocked = crtsh_certs("example.com")
        assert blocked["data"] == []
        assert str(status) in blocked["warnings"][0]
        assert "env var" in blocked["warnings"][0]

    aged = tmp_path / "aged"
    aged.mkdir()
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(aged))
    params = source._params("example.com", include_subdomains=True, include_expired=False)
    cache = HttpCache(aged / "http_cache.sqlite")
    key = cache.key("GET", source.API, params, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=EXAMPLE, ttl=86400)
    with sqlite3.connect(aged / "http_cache.sqlite") as conn:
        conn.execute(
            "UPDATE http_cache SET fetched_at = ? WHERE key = ?",
            (time.time() - 100_000, key),
        )

    def timed_out(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    assert "simulated" in (FIXTURES / "crtsh_timeout").read_text(encoding="utf-8")
    source._TRANSPORT = httpx.MockTransport(timed_out)
    stale = crtsh_certs("example.com")
    assert stale["cache"] == "stale"
    assert stale["data"]

    def gateway(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, content=(FIXTURES / "crtsh_502.html").read_bytes())

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "gateway"))
    source._TRANSPORT = httpx.MockTransport(gateway)
    failed = crtsh_certs("example.com")
    assert failed["data"] == []
    assert "502" in failed["warnings"][0]


def test_offline_cache_and_shipped_snapshot(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_CRTSH_SNAPSHOT")
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    shipped = crtsh_certs("example.com")
    assert shipped["cache"] == "snapshot"
    assert shipped["data"]
    params = source._params("other.example", include_subdomains=False, include_expired=False)
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    key = cache.key("GET", source.API, params, b"", "anonymous")
    body = json.dumps(
        [
            {
                "issuer_name": "Cached CA",
                "common_name": "other.example",
                "name_value": "other.example",
                "id": 7,
                "entry_timestamp": "2026-10-01T00:00:00.000",
                "not_before": "2026-10-01T00:00:00",
                "not_after": "2027-04-01T00:00:00",
                "serial_number": "cached1",
            }
        ]
    ).encode()
    cache.put(key, status=200, headers={}, body=body, ttl=86400)
    hit = crtsh_certs("other.example", include_subdomains=False)
    assert hit["cache"] == "hit"
    assert hit["data"][0]["serial_number"] == "cached1"
    monkeypatch.setenv("CYBERAU_CRTSH_SNAPSHOT", str(tmp_path / "missing.json"))
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "empty"))
    unavailable = crtsh_certs("example.com")
    assert unavailable["data"] == []
    assert "unavailable" in unavailable["warnings"][0]


def test_live_health_ignores_fresh_cache(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_CRTSH_SNAPSHOT")
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    state = {"t": 0.0}
    source._CLOCK = lambda: state["t"]

    def sleeper(seconds: float) -> None:
        state["t"] += float(seconds)

    source._SLEEP = sleeper
    params = source._params("example.com", include_subdomains=False, include_expired=False)
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    key = cache.key("GET", source.API, params, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=EXAMPLE, ttl=86400)
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, content=EXAMPLE)

    source._TRANSPORT = httpx.MockTransport(handler)
    probe = connector().health(live=True)
    assert calls["n"] >= 1
    assert probe.ok is True
    assert probe.detail == "live ok"

    def fail(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503, content=b"unavailable")

    calls["n"] = 0
    source._TRANSPORT = httpx.MockTransport(fail)
    failed = connector().health(live=True)
    assert calls["n"] >= 1
    assert failed.ok is False
    assert failed.detail != "live ok"


def test_cassette_replays():
    import vcr
    from vcr.serialize import deserialize
    from vcr.serializers import yamlserializer

    path = FIXTURES / "crtsh_certs.yaml"
    requests, responses = deserialize(path.read_text(encoding="utf-8"), yamlserializer)
    assert requests and responses[0]["status"]["code"] == 200
    player = vcr.VCR(record_mode="none")
    uri = "https://crt.sh/?q=%25.example.com&output=json&exclude=expired"
    with player.use_cassette(str(path)):
        played = httpx.get(uri)
    assert played.status_code == 200
    assert played.json()[0]["serial_number"] == "abc123"


def isolated_data() -> str:
    import os

    return os.environ["CYBERAU_DATA_DIR"]
