import asyncio
import json
import os
import sqlite3
import time
from pathlib import Path

import cyberau_pspf.source as source
import httpx
import jsonschema
import pytest
import yaml
from cyberau_common.cli import main
from cyberau_common.server import build_server
from cyberau_pspf.source import (
    connector,
    pspf_list_directions,
    pspf_search,
    schema_drift,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
PACKAGE = Path(__file__).resolve().parents[1]
ENVELOPE = {
    "type": "object",
    "required": ["source", "retrieved_at", "cache", "data", "untrusted"],
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
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_PSPF_SNAPSHOT", str(FIXTURES / "pspf_snapshot_two_directions.json"))
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    source._SLEEP = lambda _seconds: None
    yield
    source._TRANSPORT = None
    source._SLEEP = time.sleep


def test_search_and_directions_quote_the_snapshot():
    search_schema = json.loads((PACKAGE / "schema" / "pspf_search.input.json").read_text())
    list_schema = json.loads((PACKAGE / "schema" / "pspf_list_directions.input.json").read_text())
    record_schema = json.loads((PACKAGE / "schema" / "pspf_search.response.json").read_text())
    direction_schema = json.loads(
        (PACKAGE / "schema" / "pspf_list_directions.response.json").read_text()
    )
    jsonschema.validate({"query": "Cisco"}, search_schema)
    jsonschema.validate({}, list_schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"query": "x"}, search_schema)

    found = pspf_search("Cisco")
    jsonschema.validate(found, ENVELOPE)
    assert found["cache"] == "snapshot"
    assert found["data_as_of"] == "2026-10-17"
    assert "not a PSPF assessment" in found["attribution"]
    assert "not endorsed by the Australian Government" in found["attribution"]
    assert found["data"][0]["id"] == "001-2026"
    assert found["data"][0]["url"].startswith("https://www.protectivesecurity.gov.au/")
    assert "<<untrusted source=pspf>>" in found["data"][0]["title"]
    assert "<<untrusted source=pspf>>" in found["data"][0]["text"]
    assert "Cisco" in found["data"][0]["text"]
    jsonschema.validate(found["data"][0], record_schema)

    listed = pspf_list_directions()
    jsonschema.validate(listed, ENVELOPE)
    assert [row["id"] for row in listed["data"]] == ["002-2026", "001-2026"]
    assert listed["data"][0]["published"] == "2026-09-29"
    assert listed["data"][0]["kind"] == "direction"
    jsonschema.validate(listed["data"][0], direction_schema)
    overview = pspf_search("overview")
    assert overview["data"][0]["id"] == "pspf-page-2026"
    assert overview["data"][0]["kind"] == "publication"


def test_empty_malformed_and_unknown_query():
    assert pspf_search("x")["warnings"]
    missing = pspf_search("not-a-real-requirement-id")
    assert missing["data"] == []
    assert "not a PSPF assessment" in missing["warnings"][0]
    assert "not a finding" in missing["warnings"][0]

    source_env = "CYBERAU_PSPF_SNAPSHOT"
    os.environ[source_env] = str(FIXTURES / "empty.json")
    listed = pspf_list_directions()
    assert listed["data"] == []
    assert "not a PSPF assessment" in listed["warnings"][0]

    os.environ[source_env] = str(FIXTURES / "malformed.txt")
    warned = pspf_search("Cisco")
    assert warned["data"] == []
    assert warned["warnings"]
    assert schema_drift({"requirements": []})
    drifted = json.loads((FIXTURES / "drift.json").read_text(encoding="utf-8"))
    assert schema_drift(drifted)
    assert "title" in schema_drift(drifted)


def test_schema_drift_fails_health():
    tools = {tool.name: tool for tool in asyncio.run(build_server(connector()).list_tools())}
    assert tools["pspf_search"].inputSchema["required"] == ["query"]
    assert tools["pspf_search"].annotations.readOnlyHint is True
    assert "minLength" in json.dumps(tools["pspf_search"].inputSchema)
    assert tools["pspf_list_directions"].inputSchema["properties"] == {}
    assert connector().health(live=False, check_schema=True).ok is True

    os.environ["CYBERAU_PSPF_SNAPSHOT"] = str(FIXTURES / "drift.json")
    failed = connector().health(live=False, check_schema=True)
    assert failed.ok is False
    assert "title" in failed.detail
    assert main(["health", "pspf", "--schema-drift"]) == 1


def test_history_keeps_a_direction_that_leaves_the_page(tmp_path, monkeypatch):
    pspf_list_directions()
    later = json.loads((FIXTURES / "pspf_snapshot_two_directions.json").read_text())
    later["directions"] = [row for row in later["directions"] if row["id"] == "002-2026"]
    path = tmp_path / "one.json"
    path.write_text(json.dumps(later), encoding="utf-8")
    monkeypatch.setenv("CYBERAU_PSPF_SNAPSHOT", str(path))
    listed = pspf_list_directions()
    assert [row["id"] for row in listed["data"]] == ["002-2026"]
    found = pspf_search("Cisco")
    assert found["data"][0]["id"] == "001-2026"


def test_fallback_ladder_auth_and_retry(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_PSPF_SNAPSHOT")
    slept: list[float] = []
    source._SLEEP = lambda seconds: slept.append(seconds)

    def http11(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        direct = "HTTP/1.1 fallback" not in request.headers.get("user-agent", "")
        if "pspf-page-2026" in url and direct:
            raise httpx.ConnectError("connection reset")
        assert "hermes-cyber-au" in request.headers.get("user-agent", "")
        if "pspf-page-2026" in url:
            body = (FIXTURES / "requirements.html").read_bytes()
        else:
            body = (FIXTURES / "home.html").read_bytes()
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(http11)
    listed = pspf_list_directions()
    assert [row["id"] for row in listed["data"]] == ["002-2026", "001-2026"]
    assert "untrusted source=pspf" in listed["data"][0]["text"]
    found = pspf_search("overview")
    assert found["data"][0]["id"] == "pspf-page-2026"
    assert found["data"][0]["published"] == "2026-07-01"

    def denied(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, content=b"no")

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "auth"))
    source._TRANSPORT = httpx.MockTransport(denied)
    refused = pspf_list_directions()
    assert refused["cache"] == "snapshot"
    assert "401" in refused["warnings"][0]
    assert "environment variable" in refused["warnings"][0]
    assert refused["data"]

    def forbidden(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, content=b"no")

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "forbidden"))
    source._TRANSPORT = httpx.MockTransport(forbidden)
    blocked = pspf_search("Cisco")
    assert "403" in blocked["warnings"][0]
    assert "environment variable" in blocked["warnings"][0]

    calls = {"n": 0}

    def retry(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "0"})
        if "pspf-page-2026" in str(request.url):
            return httpx.Response(200, content=(FIXTURES / "requirements.html").read_bytes())
        return httpx.Response(200, content=(FIXTURES / "home.html").read_bytes())

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "retry"))
    source._TRANSPORT = httpx.MockTransport(retry)
    recovered = pspf_list_directions()
    assert recovered["data"][0]["id"] == "002-2026"
    assert calls["n"] >= 2
    assert 0 in slept or 0.0 in slept


def test_timeout_uses_cache_then_snapshot(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_PSPF_SNAPSHOT")

    def ok(request: httpx.Request) -> httpx.Response:
        if "pspf-page-2026" in str(request.url):
            return httpx.Response(200, content=(FIXTURES / "requirements.html").read_bytes())
        return httpx.Response(200, content=(FIXTURES / "home.html").read_bytes())

    source._TRANSPORT = httpx.MockTransport(ok)
    assert pspf_list_directions()["data"]
    cache_path = Path(os.environ["CYBERAU_DATA_DIR"]) / "http_cache.sqlite"
    with sqlite3.connect(cache_path) as conn:
        conn.execute("UPDATE http_cache SET fetched_at = 0")

    def fail(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("timed out")

    source._TRANSPORT = httpx.MockTransport(fail)
    stale = pspf_list_directions()
    assert stale["cache"] == "stale"
    assert stale["data"]
    assert stale["warnings"]

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "cold"))
    cold = pspf_list_directions()
    assert cold["cache"] == "snapshot"
    assert "served shipped snapshot" in cold["warnings"][0]
    assert cold["data"][0]["id"] == "002-2026"


def test_partial_live_page_keeps_shipped_directions(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_PSPF_SNAPSHOT")

    def partial(request: httpx.Request) -> httpx.Response:
        if "pspf-page-2026" in str(request.url):
            return httpx.Response(200, content=(FIXTURES / "requirements.html").read_bytes())
        return httpx.Response(200, content=b"<html><body><p>Publications</p></body></html>")

    source._TRANSPORT = httpx.MockTransport(partial)
    listed = pspf_list_directions()
    assert [row["id"] for row in listed["data"]] == ["002-2026", "001-2026"]
    assert "shipped snapshot" in listed["warnings"][0]
    assert "not a PSPF assessment" in listed["attribution"]


def test_redirect_is_refused(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_PSPF_SNAPSHOT")

    def redirect(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/stolen"})

    source._TRANSPORT = httpx.MockTransport(redirect)
    refused = pspf_list_directions()
    assert refused["warnings"]
    assert "evil.example" in refused["warnings"][0] or "allow" in refused["warnings"][0].lower()


def test_live_health_and_malformed_page(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_PSPF_SNAPSHOT")
    calls = {"n": 0}

    def pages(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if "pspf-page-2026" in str(request.url):
            return httpx.Response(200, content=(FIXTURES / "requirements.html").read_bytes())
        return httpx.Response(200, content=(FIXTURES / "home.html").read_bytes())

    source._TRANSPORT = httpx.MockTransport(pages)
    live = connector().health(live=True)
    assert live.ok is True
    assert calls["n"] >= 1
    assert main(["health", "pspf", "--live"]) == 0

    def garbage(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'{"directions":')

    source._TRANSPORT = httpx.MockTransport(garbage)
    warned = pspf_search("Cisco")
    assert warned["warnings"]
    assert isinstance(warned["data"], list)


def test_cassettes_have_no_secrets():
    for name in ("pspf_search.yaml", "pspf_list_directions.yaml"):
        text = (FIXTURES / name).read_text(encoding="utf-8")
        payload = yaml.safe_load(text)
        assert payload["interactions"][0]["response"]["status"]["code"] == 200
        assert "authorization:" not in text.lower()
