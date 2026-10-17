import asyncio
import json
import time
from pathlib import Path

import cyberau_threatsieve.source as source
import httpx
from cyberau_common.cache import HttpCache
from cyberau_common.server import build_server
from cyberau_threatsieve.source import connector, schema_drift, threatsieve_assess

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SECRET = "test-key-not-real"
DOMAIN = (FIXTURES / "assess_domain.json").read_bytes()


def _offline(monkeypatch, name: str):
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_THREATSIEVE_SNAPSHOT", str(FIXTURES / name))
    monkeypatch.setenv("THREATSIEVE_API_KEY", SECRET)


def _arm(monkeypatch, handler):
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.delenv("CYBERAU_THREATSIEVE_SNAPSHOT", raising=False)
    monkeypatch.setenv("THREATSIEVE_API_KEY", SECRET)
    monkeypatch.setenv("THREATSIEVE_URL", "http://127.0.0.1:8787")
    source._TRANSPORT = httpx.MockTransport(handler)
    source._SLEEPER = lambda _delay: None
    source._RNG = lambda: 0.0


def _disarm():
    source._TRANSPORT = None
    source._SLEEPER = None
    source._RNG = None


def test_domain_and_unknown_assessments(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    _offline(monkeypatch, "assess_domain.json")
    found = threatsieve_assess("  example.com  ")
    assert found["cache"] == "snapshot"
    assert found["attribution"].startswith("ThreatSieve.")
    assert found["untrusted"] is True
    assert found["data"][0]["classification"] == "benign"
    assert found["data"][0]["assessment_id"] == "asm_example_com"
    assert found["data"][0]["attack"] == ["T1566"]
    assert "<<untrusted source=threatsieve>>" in found["data"][0]["observable"]
    assert "<<untrusted source=threatsieve>>" in found["data"][0]["actors"][0]["name"]
    assert "<<untrusted source=threatsieve>>" in found["data"][0]["evidence"][0]
    history = (tmp_path / "threatsieve-observations.jsonl").read_text(encoding="utf-8")
    assert "asm_example_com" in history
    assert SECRET not in history
    assert SECRET not in json.dumps(found)
    _offline(monkeypatch, "assess_unknown.json")
    unknown = threatsieve_assess("unknown.example")
    assert unknown["data"][0]["classification"] == "unknown"
    assert unknown["data"][0]["actors"] == []
    assert unknown["data"][0]["evidence"] == []


def test_empty_malformed_and_drift(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    _offline(monkeypatch, "assess_domain.json")
    missing = threatsieve_assess("missing.example")
    assert missing["data"] == []
    assert missing["warnings"]
    assert threatsieve_assess("")["warnings"]
    assert threatsieve_assess("x" * 8193)["warnings"]
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    monkeypatch.setenv("CYBERAU_THREATSIEVE_SNAPSHOT", str(broken))
    warned = threatsieve_assess("example.com")
    assert warned["data"] == []
    assert warned["warnings"]
    assert "exception" not in warned["warnings"][0].lower()
    drift_path = FIXTURES / "assess_drift.json"
    monkeypatch.setenv("CYBERAU_THREATSIEVE_SNAPSHOT", str(drift_path))
    drifted = threatsieve_assess("example.com")
    assert drifted["data"] == []
    assert "assessment_id" in drifted["warnings"][0]
    assert schema_drift(json.loads(drift_path.read_text(encoding="utf-8")))
    monkeypatch.setenv("CYBERAU_THREATSIEVE_SNAPSHOT", str(FIXTURES / "assess_domain.json"))
    ok = connector().health(live=False, check_schema=True)
    monkeypatch.setenv("CYBERAU_THREATSIEVE_SNAPSHOT", str(drift_path))
    failed = connector().health(live=False, check_schema=True)
    assert ok.ok is True
    assert failed.ok is False
    assert "assessment_id" in failed.detail


def test_advertised_schema_and_route_list(monkeypatch):
    listed = asyncio.run(build_server(connector()).list_tools())
    tools = {tool.name: tool for tool in listed}
    schema = tools["threatsieve_assess"].inputSchema
    assert schema["required"] == ["indicator"]
    assert tools["threatsieve_assess"].annotations.readOnlyHint is True
    assert tools["threatsieve_assess"].annotations.openWorldHint is True
    stored = json.loads(
        (FIXTURES.parents[1] / "schema" / "threatsieve_assess.input.json").read_text()
    )
    assert stored["required"] == ["indicator"]
    assert stored["properties"]["indicator"]["type"] == "string"
    assert source.RATE < 5
    assert source.BURST < 5
    monkeypatch.delenv("THREATSIEVE_URL", raising=False)
    assert source._assess_url() == "http://127.0.0.1:8787/v1/assess"


def test_auth_errors_name_the_env_var(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))

    def denied(status: int, code: str):
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "POST"
            assert request.url.path == "/v1/assess"
            assert json.loads(request.content) == {"observable": "example.com"}
            assert request.headers["authorization"] == f"Bearer {SECRET}"
            body = json.dumps({"error": {"code": code, "message": "nope"}}).encode()
            return httpx.Response(status, content=body)

        return handler

    _arm(monkeypatch, denied(401, "UNAUTHORIZED"))
    try:
        refused = threatsieve_assess("example.com")
    finally:
        _disarm()
    assert refused["data"] == []
    assert "THREATSIEVE_API_KEY" in refused["warnings"][0]
    assert "401" in refused["warnings"][0]
    assert SECRET not in json.dumps(refused)

    _arm(monkeypatch, denied(403, "FORBIDDEN"))
    try:
        forbidden = threatsieve_assess("example.com")
    finally:
        _disarm()
    assert "403" in forbidden["warnings"][0]
    assert "THREATSIEVE_API_KEY" in forbidden["warnings"][0]

    monkeypatch.delenv("THREATSIEVE_API_KEY", raising=False)
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.delenv("CYBERAU_THREATSIEVE_SNAPSHOT", raising=False)
    missing_key = threatsieve_assess("example.com")
    assert "THREATSIEVE_API_KEY" in missing_key["warnings"][0]
    probe = connector().health(live=True)
    assert probe.ok is False
    assert "THREATSIEVE_API_KEY" in probe.detail


def test_retry_after_redirect_timeout_and_cache(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    calls = {"n": 0}

    def retry(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "0"})
        assert request.url.path == "/v1/assess"
        return httpx.Response(200, content=DOMAIN)

    _arm(monkeypatch, retry)
    try:
        found = threatsieve_assess("example.com")
    finally:
        _disarm()
    assert calls["n"] == 2
    assert found["data"][0]["assessment_id"] == "asm_example_com"
    assert found["cache"] == "miss"

    def redirect(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.test/steal"})

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "redirect"))
    _arm(monkeypatch, redirect)
    try:
        refused = threatsieve_assess("example.com")
    finally:
        _disarm()
    assert refused["data"] == []
    assert "evil.test" in refused["warnings"][0]

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "timeout"))
    monkeypatch.setenv("THREATSIEVE_API_KEY", SECRET)
    monkeypatch.setenv("THREATSIEVE_URL", "http://127.0.0.1:8787")
    cache = HttpCache(tmp_path / "timeout" / "http_cache.sqlite", now=lambda: time.time() - 1000)
    cache.put(
        source.request_cache_key("example.com"),
        status=200,
        headers={},
        body=DOMAIN,
        ttl=source.TTL,
    )

    def time_out(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("timed out")

    _arm(monkeypatch, time_out)
    try:
        stale = threatsieve_assess("example.com")
    finally:
        _disarm()
    assert stale["cache"] == "stale"
    assert stale["data"][0]["assessment_id"] == "asm_example_com"

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "down"))
    _arm(monkeypatch, time_out)
    try:
        down = threatsieve_assess("example.com")
    finally:
        _disarm()
    assert down["data"] == []
    assert "unavailable" in down["warnings"][0].lower()


def test_live_health_ignores_fresh_cache(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("THREATSIEVE_API_KEY", SECRET)
    monkeypatch.setenv("THREATSIEVE_URL", "http://127.0.0.1:8787")
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    cache.put(
        source.request_cache_key("example.com"),
        status=200,
        headers={},
        body=DOMAIN,
        ttl=source.TTL,
    )
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        assert request.url.path == "/v1/assess"
        return httpx.Response(200, content=DOMAIN)

    _arm(monkeypatch, handler)
    try:
        probe = connector().health(live=True, check_schema=True)
    finally:
        _disarm()
    assert calls["n"] == 1
    assert probe.ok is True
    assert probe.detail == "live ok"


def test_url_drops_userinfo_and_query(monkeypatch):
    monkeypatch.setenv(
        "THREATSIEVE_URL",
        "http://user:secret@127.0.0.1:8787/custom?api_key=sekret",
    )
    assert source._assess_url() == "http://127.0.0.1:8787/v1/assess"
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_THREATSIEVE_SNAPSHOT", str(FIXTURES / "assess_domain.json"))
    found = threatsieve_assess("example.com")
    rendered = json.dumps(found)
    assert "sekret" not in rendered
    assert "user:secret" not in rendered
    assert found["source_urls"] == ["http://127.0.0.1:8787/v1/assess"]


def test_cassette_has_no_secret_and_replays():
    import vcr
    from vcr.serialize import deserialize
    from vcr.serializers import yamlserializer

    path = FIXTURES / "threatsieve_assess.yaml"
    text = path.read_text(encoding="utf-8")
    assert "Bearer " not in text
    assert SECRET not in text
    requests, responses = deserialize(text, yamlserializer)
    assert requests and responses[0]["status"]["code"] == 200
    player = vcr.VCR(record_mode="none")
    with player.use_cassette(str(path)):
        played = httpx.post(
            "http://127.0.0.1:8787/v1/assess",
            content=b'{"observable":"example.com"}',
            headers={"content-type": "application/json"},
        )
    assert played.status_code == 200
    assert played.json()["assessment_id"] == "asm_example_com"


def test_fixtures_have_no_secrets():
    for path in FIXTURES.iterdir():
        text = path.read_text(encoding="utf-8")
        assert "Bearer " not in text
        assert "THREATSIEVE_API_KEY=" not in text
