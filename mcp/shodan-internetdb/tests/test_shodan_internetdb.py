import asyncio
import json
from pathlib import Path
from urllib.parse import unquote

import cyberau_shodan_internetdb.source as source
import httpx
import jsonschema
import pytest
from cyberau_common.cache import HttpCache
from cyberau_common.server import build_server
from cyberau_shodan_internetdb.source import (
    connector,
    internetdb_ip,
    schema_drift,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
PACKAGE = Path(__file__).resolve().parents[1]
ENVELOPE = {
    "type": "object",
    "required": ["source", "retrieved_at", "cache", "data", "untrusted", "attribution"],
    "properties": {
        "source": {"type": "string"},
        "source_urls": {"type": "array", "items": {"type": "string"}},
        "retrieved_at": {"type": "string"},
        "data_as_of": {"type": ["string", "null"]},
        "cache": {"enum": ["hit", "miss", "stale", "snapshot"]},
        "attribution": {"type": "string"},
        "untrusted": {"const": True},
        "warnings": {"type": "array", "items": {"type": "string"}},
        "data": {},
    },
}


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_INTERNETDB_SNAPSHOT", str(FIXTURES / "ip_hit.json"))
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(source, "_TRANSPORT", None)


def test_hit_validates_schemas_and_wraps_text(tmp_path):
    found = internetdb_ip("1.1.1.1")
    jsonschema.validate(found, ENVELOPE)
    response = json.loads((PACKAGE / "schema" / "internetdb_ip.response.json").read_text())
    entered = json.loads((PACKAGE / "schema" / "internetdb_ip.input.json").read_text())
    jsonschema.validate({"ip": "1.1.1.1"}, entered)
    jsonschema.validate(found["data"], response)
    assert found["attribution"].startswith("Shodan InternetDB")
    assert found["cache"] == "snapshot"
    assert 443 in found["data"]["ports"]
    assert found["data"]["cpes"] == ["cpe:/a:cloudflare:cloudflare"]
    assert "<<untrusted source=shodan-internetdb>>" in found["data"]["hostnames"][0]
    assert "one.one.one.one" in found["data"]["hostnames"][0]
    stored = (tmp_path / "internetdb-observations.jsonl").read_text(encoding="utf-8")
    assert "1.1.1.1" in stored
    assert "Bearer " not in stored


def test_empty_invalid_and_malformed(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_INTERNETDB_SNAPSHOT", str(FIXTURES / "ip_404.json"))
    empty = internetdb_ip("192.0.2.1")
    assert empty["data"]["ports"] == []
    assert empty["data"]["hostnames"] == []
    assert empty["warnings"]
    assert not (tmp_path / "internetdb-observations.jsonl").exists()

    rejected = internetdb_ip("example")
    assert rejected["data"] is None
    assert rejected["cache"] == "snapshot"
    assert "IPv4 or IPv6" in rejected["warnings"][0]

    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    monkeypatch.setenv("CYBERAU_INTERNETDB_SNAPSHOT", str(broken))
    warned = internetdb_ip("1.1.1.1")
    assert warned["data"] is None
    assert warned["warnings"]

    monkeypatch.setenv("CYBERAU_INTERNETDB_SNAPSHOT", str(FIXTURES / "ip_drift.json"))
    drifted = internetdb_ip("1.1.1.1")
    assert drifted["data"] is None
    assert "schema drift" in drifted["warnings"][0]
    assert schema_drift(json.loads((FIXTURES / "ip_404.json").read_text())) is None
    monkeypatch.setenv("CYBERAU_INTERNETDB_SNAPSHOT", str(FIXTURES / "ip_hit.json"))
    other = internetdb_ip("8.8.8.8")
    assert other["data"]["ports"] == []
    assert other["warnings"]


def test_tags_are_untrusted_text(tmp_path, monkeypatch):
    payload = json.loads((FIXTURES / "ip_hit.json").read_text(encoding="utf-8"))
    payload["tags"] = ["vpn\u202ehidden"]
    path = tmp_path / "tagged.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("CYBERAU_INTERNETDB_SNAPSHOT", str(path))
    found = internetdb_ip("1.1.1.1")
    tag = found["data"]["tags"][0]
    assert "<<untrusted source=shodan-internetdb>>" in tag
    assert "\u202e" not in tag
    assert "vpnhidden" in tag


def test_advertised_schema_and_drift_probe(monkeypatch):
    tools = {tool.name: tool for tool in asyncio.run(build_server(connector()).list_tools())}
    tool = tools["internetdb_ip"]
    assert tool.inputSchema["required"] == ["ip"]
    assert tool.annotations.readOnlyHint is True
    assert tool.annotations.openWorldHint is True
    assert len("mcp__internetdb__internetdb_ip") == 30
    assert connector().health(live=False, check_schema=True).ok is True
    monkeypatch.setenv("CYBERAU_INTERNETDB_SNAPSHOT", str(FIXTURES / "ip_drift.json"))
    failed = connector().health(live=False, check_schema=True)
    assert failed.ok is False
    assert "ports" in failed.detail


def test_offline_cache_snapshot_and_unavailable(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_INTERNETDB_SNAPSHOT")
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    shipped = internetdb_ip("1.1.1.1")
    assert shipped["cache"] == "snapshot"
    assert 53 in shipped["data"]["ports"]

    body = json.dumps(
        {
            "ip": "8.8.8.8",
            "ports": [53],
            "hostnames": ["dns.google"],
            "cpes": [],
            "tags": ["resolver"],
            "vulns": [],
        }
    ).encode()
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    url = source._url("8.8.8.8")
    key = cache.key("GET", url, None, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=body, ttl=86400)
    found = internetdb_ip("8.8.8.8")
    assert found["cache"] in {"hit", "stale"}
    assert found["data"]["ports"] == [53]
    assert "dns.google" in found["data"]["hostnames"][0]

    monkeypatch.setenv("CYBERAU_INTERNETDB_SNAPSHOT", str(tmp_path / "missing.json"))
    missing = internetdb_ip("1.1.1.1")
    assert missing["data"] is None
    assert "unavailable" in missing["warnings"][0]


def test_http_retry_redirect_auth_and_timeout(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_INTERNETDB_SNAPSHOT")
    hit = (FIXTURES / "ip_hit.json").read_bytes()
    calls = {"n": 0}

    def retry(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "0"})
        return httpx.Response(200, content=hit)

    source._TRANSPORT = httpx.MockTransport(retry)
    found = internetdb_ip("1.1.1.1")
    assert calls["n"] >= 2
    assert 443 in found["data"]["ports"]

    def redirect(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.test/x"})

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "redirect"))
    source._TRANSPORT = httpx.MockTransport(redirect)
    refused = internetdb_ip("1.1.1.1")
    assert refused["warnings"]
    assert "evil.test" in refused["warnings"][0]

    for status in (401, 403):
        monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / str(status)))
        source._TRANSPORT = httpx.MockTransport(
            lambda _request, status=status: httpx.Response(status, json={"detail": "no"})
        )
        denied = internetdb_ip("1.1.1.1")
        assert denied["data"] is None
        assert str(status) in denied["warnings"][0]
        assert "env var" in denied["warnings"][0]

    stale_dir = tmp_path / "stale"
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(stale_dir))
    cache = HttpCache(stale_dir / "http_cache.sqlite")
    url = source._url("1.1.1.1")
    key = cache.key("GET", url, None, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=hit, ttl=0)

    def timeout(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    source._TRANSPORT = httpx.MockTransport(timeout)
    cached = internetdb_ip("1.1.1.1")
    assert cached["cache"] == "stale"
    assert cached["data"]["ip"] == "1.1.1.1"


def test_ipv6_path_and_live_health(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_INTERNETDB_SNAPSHOT")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = unquote(request.url.path)
        if request.url.path.endswith("1111"):
            return httpx.Response(404, json={"detail": "No information available"})
        return httpx.Response(200, content=(FIXTURES / "ip_hit.json").read_bytes())

    source._TRANSPORT = httpx.MockTransport(handler)
    missed = internetdb_ip("2606:4700:4700::1111")
    assert seen["path"] == "/2606:4700:4700::1111"
    assert missed["data"]["ports"] == []

    calls = {"n": 0}

    def live(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        assert request.url.path == "/1.1.1.1"
        return httpx.Response(200, content=(FIXTURES / "ip_hit.json").read_bytes())

    source._TRANSPORT = httpx.MockTransport(live)
    probe = connector().health(live=True)
    assert calls["n"] == 1
    assert probe.ok is True
    assert probe.detail == "live ok"

    source._TRANSPORT = httpx.MockTransport(
        lambda _request: httpx.Response(503, content=b"unavailable")
    )
    failed = connector().health(live=True)
    assert failed.ok is False
    assert "503" in failed.detail


def test_cassette_has_no_secrets_and_replays():
    import vcr
    from vcr.serialize import deserialize
    from vcr.serializers import yamlserializer

    path = FIXTURES / "internetdb_ip.yaml"
    text = path.read_text(encoding="utf-8")
    assert "authorization:" not in text.lower()
    assert "api_key" not in text.lower()
    requests, responses = deserialize(text, yamlserializer)
    assert requests and responses[0]["status"]["code"] == 200
    body = json.loads(responses[0]["body"]["string"])
    assert body == json.loads((FIXTURES / "ip_hit.json").read_text(encoding="utf-8"))
    player = vcr.VCR(record_mode="none")
    with player.use_cassette(str(path)):
        played = httpx.get("https://internetdb.shodan.io/1.1.1.1")
    assert played.status_code == 200
    assert played.json()["ip"] == "1.1.1.1"
