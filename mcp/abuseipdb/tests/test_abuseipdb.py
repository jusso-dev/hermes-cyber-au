import json
import random
import sqlite3
import time
from pathlib import Path

import cyberau_abuseipdb.source as source
import httpx
import jsonschema
import pytest
from cyberau_abuseipdb.source import (
    CHECK_URL,
    abuseipdb_check_block,
    abuseipdb_check_ip,
    connector,
    schema_drift,
)
from cyberau_common.cache import HttpCache
from cyberau_common.cli import main
from cyberau_common.server import build_server

FIXTURES = Path(__file__).resolve().parent / "fixtures"
KEY = "fixture-abuseipdb-key"
_PRIVATE = (
    "10.1.2.3",
    "172.16.0.1",
    "192.168.0.1",
    "127.0.0.1",
    "169.254.1.1",
    "100.64.1.1",
    "192.0.2.1",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "240.0.0.1",
    "255.255.255.255",
    "0.0.0.0",
    "::1",
    "fc00::1",
    "fe80::1",
    "2001:db8::1",
)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_ABUSEIPDB_SNAPSHOT", str(FIXTURES / "check_ip.json"))
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    yield
    source._TRANSPORT = None
    source._SLEEP = time.sleep
    source._RNG = random.random


def _online(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.delenv("CYBERAU_ABUSEIPDB_SNAPSHOT", raising=False)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", KEY)


def _body(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_check_ip_and_block_happy_path(tmp_path, monkeypatch):
    found = abuseipdb_check_ip("118.25.6.39")
    assert found["cache"] == "snapshot"
    assert found["attribution"].startswith("AbuseIPDB")
    assert found["data"]["abuse_confidence_score"] == 100
    assert found["data"]["total_reports"] == 1
    assert found["data"]["country_code"] == "CN"
    assert "<<untrusted source=abuseipdb>>" in found["data"]["isp"]
    assert "<<untrusted source=abuseipdb>>" in found["data"]["usage_type"]
    assert "<<untrusted source=abuseipdb>>" in found["data"]["domain"]
    assert "<<untrusted source=abuseipdb>>" in found["data"]["hostnames"][0]
    schema = json.loads(
        (FIXTURES.parents[1] / "schema" / "abuseipdb_check_ip.response.json").read_text()
    )
    jsonschema.validate(found["data"], schema)
    observations = (tmp_path / "abuseipdb-observations.jsonl").read_text(encoding="utf-8")
    assert "118.25.6.39" in observations
    assert KEY not in json.dumps(found)

    monkeypatch.setenv("CYBERAU_ABUSEIPDB_SNAPSHOT", str(FIXTURES / "check_block.json"))
    block = abuseipdb_check_block("1.1.1.1/24")
    assert block["data"]["network"] == "1.1.1.0/24"
    assert block["data"]["reported"][0]["abuse_confidence_score"] == 12
    assert block["data"]["reported"][0]["country_code"] == "AU"
    assert "<<untrusted source=abuseipdb>>" in block["data"]["address_space"]
    block_schema = json.loads(
        (FIXTURES.parents[1] / "schema" / "abuseipdb_check_block.response.json").read_text()
    )
    jsonschema.validate(block["data"], block_schema)
    envelope = {
        "type": "object",
        "required": ["source", "retrieved_at", "cache", "data", "untrusted", "attribution"],
        "properties": {"attribution": {"type": "string"}, "untrusted": {"const": True}},
    }
    jsonschema.validate(found, envelope)
    jsonschema.validate(block, envelope)


def test_empty_malformed_and_age(monkeypatch):
    monkeypatch.setenv("CYBERAU_ABUSEIPDB_SNAPSHOT", str(FIXTURES / "check_block_empty.json"))
    empty = abuseipdb_check_block("8.8.8.0/24")
    assert empty["data"]["reported"] == []
    assert empty["warnings"] == []
    monkeypatch.setenv("CYBERAU_ABUSEIPDB_SNAPSHOT", str(FIXTURES / "check_block.json"))
    missing = abuseipdb_check_block("8.8.8.0/24")
    assert missing["data"]["reported"] == []
    assert missing["warnings"]
    monkeypatch.setenv("CYBERAU_ABUSEIPDB_SNAPSHOT", str(FIXTURES / "abuseipdb_malformed.json"))
    warned = abuseipdb_check_ip("118.25.6.39")
    assert warned["warnings"]
    assert warned["data"] is None
    monkeypatch.setenv("CYBERAU_ABUSEIPDB_SNAPSHOT", str(FIXTURES / "abuseipdb_401.json"))
    drifted = abuseipdb_check_ip("118.25.6.39")
    assert drifted["warnings"]
    assert abuseipdb_check_ip("118.25.6.39", max_age_days=0)["warnings"]
    assert abuseipdb_check_ip("118.25.6.39", max_age_days=True)["warnings"]
    assert abuseipdb_check_ip("example")["warnings"]
    assert abuseipdb_check_block("not-a-network")["warnings"]


def test_private_and_reserved_addresses_do_not_use_the_network(monkeypatch):
    _online(monkeypatch)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(500, content=b"should not be called")

    source._TRANSPORT = httpx.MockTransport(handler)
    for address in _PRIVATE:
        refused = abuseipdb_check_ip(address)
        assert refused["data"] is None
        assert "private and reserved" in refused["warnings"][0]
    refused_block = abuseipdb_check_block("10.1.2.0/24")
    assert "private and reserved" in refused_block["warnings"][0]
    too_big = abuseipdb_check_block("1.1.0.0/16")
    assert "/24" in too_big["warnings"][0]
    multicast = abuseipdb_check_block("224.0.0.0/24")
    assert "private and reserved" in multicast["warnings"][0]
    assert calls["n"] == 0


def test_auth_errors_name_the_env_var(monkeypatch):
    _online(monkeypatch)
    calls = {"n": 0}

    def missing_key(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(500)

    source._TRANSPORT = httpx.MockTransport(missing_key)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    missing = abuseipdb_check_ip("118.25.6.39")
    assert "ABUSEIPDB_API_KEY" in missing["warnings"][0]
    assert calls["n"] == 0

    def rejected(status: int):
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["key"] == KEY
            assert "key=" not in str(request.url)
            body = (FIXTURES / "abuseipdb_401.json").read_bytes()
            return httpx.Response(status, content=body)

        return handler

    for status in (401, 403):
        source._TRANSPORT = httpx.MockTransport(rejected(status))
        monkeypatch.setenv("ABUSEIPDB_API_KEY", KEY)
        result = abuseipdb_check_ip("118.25.6.39")
        assert "ABUSEIPDB_API_KEY" in result["warnings"][0]
        assert f"HTTP {status}" in result["warnings"][0]
        assert KEY not in json.dumps(result)


def test_daily_limit_honours_retry_after(monkeypatch, tmp_path):
    _online(monkeypatch)
    delays = []
    calls = {"n": 0}
    source._SLEEP = delays.append

    def retry(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            body = (FIXTURES / "abuseipdb_429_daily.json").read_bytes()
            return httpx.Response(429, headers={"retry-after": "2"}, content=body)
        return httpx.Response(200, content=(FIXTURES / "check_ip.json").read_bytes())

    source._TRANSPORT = httpx.MockTransport(retry)
    found = abuseipdb_check_ip("118.25.6.39")
    assert found["data"]["abuse_confidence_score"] == 100
    assert 2.0 in delays

    def always(request: httpx.Request) -> httpx.Response:
        body = (FIXTURES / "abuseipdb_429_daily.json").read_bytes()
        return httpx.Response(429, headers={"retry-after": "0"}, content=body)

    source._TRANSPORT = httpx.MockTransport(always)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "limited"))
    limited = abuseipdb_check_ip("1.1.1.1")
    assert "429" in limited["warnings"][0]
    assert "Retry-After" in limited["warnings"][0]


def test_timeout_falls_back_to_cache(monkeypatch, tmp_path):
    _online(monkeypatch)
    source._SLEEP = lambda _delay: None
    source._RNG = lambda: 0
    body = json.dumps(_body("check_ip.json")).encode()
    payload = json.loads(body)
    payload["data"]["ipAddress"] = "1.1.1.1"
    encoded = json.dumps(payload).encode()
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    params = {"ipAddress": "1.1.1.1", "maxAgeInDays": "90"}
    key = cache.key("GET", CHECK_URL, params, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=encoded, ttl=0)

    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    source._TRANSPORT = httpx.MockTransport(fail)
    found = abuseipdb_check_ip("1.1.1.1")
    assert found["cache"] == "stale"
    assert found["data"]["ip"] == "1.1.1.1"
    assert found["warnings"] == []


def test_redirect_off_the_allowlist_is_refused(monkeypatch):
    _online(monkeypatch)

    def redirect(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.test/x"})

    source._TRANSPORT = httpx.MockTransport(redirect)
    refused = abuseipdb_check_ip("118.25.6.39")
    assert refused["warnings"]
    assert KEY not in json.dumps(refused)
    assert refused["data"] is None


def test_schema_drift_fails_health(monkeypatch):
    probe = connector().health(live=False, check_schema=True)
    assert probe.ok is True
    monkeypatch.setenv("CYBERAU_ABUSEIPDB_SNAPSHOT", str(FIXTURES / "abuseipdb_drift.json"))
    failed = connector().health(live=False, check_schema=True)
    assert failed.ok is False
    assert "abuseConfidenceScore" in failed.detail
    assert schema_drift(_body("abuseipdb_drift.json"))
    assert main(["health", "abuseipdb", "--schema-drift"]) == 1


def test_live_health_validates_the_response_schema(monkeypatch, tmp_path):
    _online(monkeypatch)

    def ok(request: httpx.Request) -> httpx.Response:
        assert request.url.params["ipAddress"] == "1.1.1.1"
        assert request.url.params["maxAgeInDays"] == "1"
        body = json.dumps(_body("check_ip.json")).encode()
        payload = json.loads(body)
        payload["data"]["ipAddress"] = "1.1.1.1"
        return httpx.Response(200, content=json.dumps(payload).encode())

    source._TRANSPORT = httpx.MockTransport(ok)
    probe = connector().health(live=True)
    assert probe.ok is True
    assert probe.detail == "live ok"
    database = sqlite3.connect(tmp_path / "rate_limit.sqlite")
    keys = {row[0] for row in database.execute("select key from rolling")}
    assert "abuseipdb:check" in keys


def test_advertised_schema_and_cassettes(vcr_config):
    import asyncio

    listed = asyncio.run(build_server(connector()).list_tools())
    tools = {tool.name: tool for tool in listed}
    check = tools["abuseipdb_check_ip"]
    block = tools["abuseipdb_check_block"]
    assert check.annotations.readOnlyHint is True
    assert check.annotations.openWorldHint is True
    encoded = json.dumps(check.inputSchema)
    assert "IPv4 or IPv6 address" in encoded
    assert "maximum" in encoded
    assert block.inputSchema["required"] == ["network"]
    assert len("mcp__abuseipdb__abuseipdb_check_ip") == 34
    assert len("mcp__abuseipdb__abuseipdb_check_block") == 37
    assert "key" in vcr_config["filter_headers"]
    for name in ("abuseipdb_check_ip.yaml", "abuseipdb_check_block.yaml"):
        text = (FIXTURES / name).read_text(encoding="utf-8")
        assert "Key:" not in text
        assert KEY not in text


def test_cassettes_replay():
    import vcr
    from vcr.serialize import deserialize
    from vcr.serializers import yamlserializer

    uris = {
        "abuseipdb_check_ip": (
            "https://api.abuseipdb.com/api/v2/check?ipAddress=118.25.6.39&maxAgeInDays=90"
        ),
        "abuseipdb_check_block": "https://api.abuseipdb.com/api/v2/check-block?network=1.1.1.0/24",
    }
    player = vcr.VCR(record_mode="none", filter_headers=["key"])
    for name, uri in uris.items():
        path = FIXTURES / f"{name}.yaml"
        requests, responses = deserialize(path.read_text(encoding="utf-8"), yamlserializer)
        assert requests and responses[0]["status"]["code"] == 200
        with player.use_cassette(str(path)):
            played = httpx.get(uri)
        assert played.status_code == 200
        assert played.json()["data"]


def test_offline_without_a_snapshot_uses_the_package_or_says_unavailable(monkeypatch, tmp_path):
    monkeypatch.delenv("CYBERAU_ABUSEIPDB_SNAPSHOT", raising=False)
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    found = abuseipdb_check_ip("118.25.6.39")
    assert found["cache"] == "snapshot"
    assert found["data"]["ip"] == "118.25.6.39"
    other = abuseipdb_check_ip("1.1.1.1")
    assert other["data"] is None
    assert other["warnings"]
    monkeypatch.setenv("CYBERAU_ABUSEIPDB_SNAPSHOT", str(tmp_path / "missing.json"))
    unavailable = abuseipdb_check_ip("8.8.8.8")
    assert "unavailable" in unavailable["warnings"][0].lower()


def test_fixtures_have_no_secrets():
    for path in FIXTURES.iterdir():
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        assert "bearer " not in lowered
        assert "apikey" not in lowered
        assert KEY not in text
