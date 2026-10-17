import asyncio
import json
import time
from pathlib import Path

import cyberau_greynoise.source as source
import httpx
import jsonschema
import pytest
from cyberau_common.cache import HttpCache
from cyberau_common.server import build_server
from cyberau_greynoise.source import COMMUNITY_API, connector, greynoise_ip, schema_drift

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ROOT = Path(__file__).resolve().parents[1]
ENVELOPE = {
    "type": "object",
    "required": ["source", "retrieved_at", "cache", "data", "untrusted", "attribution"],
    "properties": {
        "source": {"type": "string"},
        "retrieved_at": {"type": "string"},
        "cache": {"enum": ["hit", "miss", "stale", "snapshot"]},
        "attribution": {"type": "string"},
        "untrusted": {"const": True},
        "warnings": {"type": "array", "items": {"type": "string"}},
        "data": {},
    },
}


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
    monkeypatch.delenv("CYBERAU_GREYNOISE_SNAPSHOT", raising=False)
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    yield
    source._TRANSPORT = None
    source._SLEEP = time.sleep
    source._LIMIT_SLEEP = time.sleep
    source._CLOCK = time.monotonic
    source._RETRIES = 3


def _snapshot(name: str, monkeypatch) -> None:
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_GREYNOISE_SNAPSHOT", str(FIXTURES / name))


def _schema(name: str) -> dict:
    return json.loads((ROOT / "schema" / name).read_text(encoding="utf-8"))


def test_noise_riot_and_schemas(tmp_path, monkeypatch):
    _snapshot("community_riot.json", monkeypatch)
    riot = greynoise_ip("1.1.1.1")
    jsonschema.validate(riot, ENVELOPE)
    jsonschema.validate(riot["data"], _schema("greynoise_ip.response.json"))
    assert riot["attribution"].startswith("GreyNoise Community")
    assert riot["data"]["riot"] is True
    assert riot["data"]["noise"] is False
    assert "<<untrusted source=greynoise>>" in riot["data"]["name"]
    assert "<<untrusted source=greynoise>>" in riot["data"]["message"]
    stored = (tmp_path / "data" / "greynoise-observations.jsonl").read_text(encoding="utf-8")
    assert "1.1.1.1" in stored

    _snapshot("community_noise.json", monkeypatch)
    noise = greynoise_ip("203.0.113.50")
    assert noise["data"]["noise"] is True
    assert noise["data"]["classification"] == "malicious"
    assert noise["cache"] == "snapshot"

    listed = asyncio.run(build_server(connector()).list_tools())
    tool = {item.name: item for item in listed}["greynoise_ip"]
    assert tool.annotations.readOnlyHint is True
    assert tool.annotations.openWorldHint is True
    assert len("mcp__greynoise__greynoise_ip") == 28
    incoming = _schema("greynoise_ip.input.json")
    jsonschema.Draft202012Validator.check_schema(incoming)
    jsonschema.validate({"ip": "203.0.113.50"}, incoming)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"ip": "203.0.113.50", "extra": True}, incoming)


def test_empty_and_renamed_field(monkeypatch):
    _snapshot("community_404_unknown.json", monkeypatch)
    missing = greynoise_ip("203.0.113.10")
    assert missing["data"] is None
    assert missing["warnings"]
    assert "<<untrusted source=greynoise>>" in missing["warnings"][0]

    _snapshot("community_429.json", monkeypatch)
    limited = greynoise_ip("203.0.113.50")
    assert limited["data"] is None
    assert "schema drift" in limited["warnings"][0]


def test_malformed_payload_warns(tmp_path, monkeypatch):
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_GREYNOISE_SNAPSHOT", str(broken))
    warned = greynoise_ip("203.0.113.50")
    assert warned["data"] is None
    assert warned["warnings"]
    assert "not usable" in warned["warnings"][0]

    _snapshot("community_drift.json", monkeypatch)
    probe = connector().health(live=False, check_schema=True)
    assert probe.ok is False
    assert "noise" in probe.detail
    assert schema_drift(json.loads((FIXTURES / "community_drift.json").read_text()))
    monkeypatch.delenv("CYBERAU_GREYNOISE_SNAPSHOT")
    assert connector().health(live=False, check_schema=True).ok is True


def test_invalid_ip_and_ipv6(tmp_path, monkeypatch):
    assert greynoise_ip("example")["warnings"]
    assert greynoise_ip("")["data"] is None
    body = {
        "ip": "2001:db8::1",
        "noise": True,
        "riot": False,
        "classification": "unknown",
        "name": "Docs Prefix",
        "message": "Success",
        "link": "https://viz.greynoise.io/ip/2001:db8::1",
        "last_seen": "2026-10-16",
    }
    path = tmp_path / "v6.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_GREYNOISE_SNAPSHOT", str(path))
    found = greynoise_ip("2001:0db8:0000::1")
    assert found["data"]["ip"] == "2001:db8::1"
    assert found["data"]["classification"] == "unknown"


def test_offline_cache_and_unavailable(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    missing = greynoise_ip("203.0.113.50")
    assert missing["data"] is None
    assert "unavailable" in missing["warnings"][0]
    packed = greynoise_ip("1.1.1.1")
    assert packed["cache"] == "snapshot"
    assert packed["data"]["riot"] is True

    monkeypatch.delenv("CYBERAU_OFFLINE")
    cache = HttpCache(tmp_path / "data" / "http_cache.sqlite")
    url = f"{COMMUNITY_API}/203.0.113.50"
    body = (FIXTURES / "community_noise.json").read_bytes()
    key = cache.key("GET", url, None, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=body, ttl=0)
    calls = {"n": 0}

    def timeout(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        raise httpx.ReadTimeout("timed out")

    source._TRANSPORT = httpx.MockTransport(timeout)
    source._RETRIES = 0
    stale = greynoise_ip("203.0.113.50")
    assert calls["n"] == 1
    assert stale["cache"] == "stale"
    assert stale["data"]["noise"] is True

    other = tmp_path / "empty"
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(other))
    source._TRANSPORT = httpx.MockTransport(timeout)
    failed = greynoise_ip("198.51.100.20")
    assert failed["data"] is None
    assert failed["warnings"]


@pytest.mark.parametrize("status", [401, 403])
def test_auth_failure_names_env(status, monkeypatch):
    monkeypatch.setenv("GREYNOISE_API_KEY", "super-secret-greynoise-value")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["key"] = request.headers.get("key")
        seen["path"] = request.url.path
        return httpx.Response(status, json={"message": "rejected"})

    source._TRANSPORT = httpx.MockTransport(handler)
    result = greynoise_ip("203.0.113.50")
    assert seen["key"] == "super-secret-greynoise-value"
    assert seen["path"] == "/v3/community/203.0.113.50"
    assert "GREYNOISE_API_KEY" in result["warnings"][0]
    assert "super-secret-greynoise-value" not in json.dumps(result)
    assert result["attribution"].startswith("GreyNoise Community")


def test_retry_after_rate_limit_and_redirect(monkeypatch):
    now = {"t": 0.0}
    http_slept: list[float] = []
    limit_slept: list[float] = []

    def clock() -> float:
        return now["t"]

    def limit_sleep(seconds: float) -> None:
        limit_slept.append(seconds)
        now["t"] += seconds

    source._CLOCK = clock
    source._LIMIT_SLEEP = limit_sleep
    source._SLEEP = http_slept.append
    calls = {"n": 0}
    body = (FIXTURES / "community_noise.json").read_bytes()

    def retry(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(
                429,
                headers={"retry-after": "2"},
                content=(FIXTURES / "community_429.json").read_bytes(),
            )
        assert request.url.path == "/v3/community/203.0.113.50"
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(retry)
    found = greynoise_ip("203.0.113.50")
    assert found["data"]["noise"] is True
    assert 2.0 in http_slept
    assert 1.0 in limit_slept

    def always_limited(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"retry-after": "0"})

    source._TRANSPORT = httpx.MockTransport(always_limited)
    source._RETRIES = 0
    blocked = greynoise_ip("198.51.100.8")
    assert blocked["data"] is None
    assert "rate limit" in blocked["warnings"][0]

    def redirect(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.test/x"})

    source._TRANSPORT = httpx.MockTransport(redirect)
    source._RETRIES = 0
    refused = greynoise_ip("203.0.113.10")
    assert refused["warnings"]
    assert "allowlisted" in refused["warnings"][0]
    assert "super-secret" not in json.dumps(refused)


def test_live_health_ignores_cache(tmp_path, monkeypatch):
    cache = HttpCache(tmp_path / "data" / "http_cache.sqlite")
    url = f"{COMMUNITY_API}/1.1.1.1"
    key = cache.key("GET", url, None, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=b'{"ip":"9.9.9.9"}', ttl=86400)
    calls = {"n": 0}
    body = (FIXTURES / "community_riot.json").read_bytes()

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(handler)
    probe = connector().health(live=True)
    assert calls["n"] == 1
    assert probe.ok is True

    def fail(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, content=b"down")

    source._TRANSPORT = httpx.MockTransport(fail)
    failed = connector().health(live=True)
    assert failed.ok is False
    assert failed.detail != "live ok"


def test_timeout_redacts_secret(monkeypatch):
    secret = "super-secret-greynoise-value"
    monkeypatch.setenv("GREYNOISE_API_KEY", secret)

    def explode(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout(f"key: {secret}")

    source._TRANSPORT = httpx.MockTransport(explode)
    source._RETRIES = 0
    result = greynoise_ip("203.0.113.50")
    rendered = json.dumps(result)
    assert secret not in rendered
    assert result["warnings"]


def test_cassette_replays_without_auth_header():
    import vcr
    from vcr.serialize import deserialize
    from vcr.serializers import yamlserializer

    path = FIXTURES / "greynoise_ip.yaml"
    text = path.read_text(encoding="utf-8")
    assert "key:" not in text.split("headers:", 1)[-1].split("response:", 1)[0]
    requests, responses = deserialize(text, yamlserializer)
    assert requests and responses[0]["status"]["code"] == 200
    player = vcr.VCR(record_mode="none", filter_headers=["key"])
    with player.use_cassette(str(path)):
        played = httpx.get(f"{COMMUNITY_API}/1.1.1.1")
    assert played.status_code == 200
    assert played.json()["riot"] is True


def test_vcr_config_filters_key(vcr_config):
    assert "key" in vcr_config["filter_headers"]
