"""Flashpoint Ignite indicator connector. No network in the default run."""

from __future__ import annotations

import asyncio
import ipaddress
import json
from datetime import date
from pathlib import Path

import cyberau_flashpoint.source as source
import httpx
import pytest
import yaml
from cyberau_common.server import build_server
from cyberau_flashpoint.source import (
    INDICATORS_URL,
    connector,
    flashpoint_indicator,
    schema_drift,
)
from cyberau_premium.base import PremiumConnector, Watchlist
from cyberau_premium.catalog import get_vendor
from cyberau_premium.status import load_servers, render_premium_servers
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

FIXTURES = Path(__file__).resolve().parent / "fixtures"
PACKAGE = Path(__file__).resolve().parents[1]
REPO = Path(__file__).resolve().parents[3]
TOKEN = "fp-test-token-value"
INPUT_SCHEMA = json.loads(
    (PACKAGE / "schema" / "flashpoint_indicator.input.json").read_text(encoding="utf-8")
)
RESPONSE_SCHEMA = json.loads(
    (PACKAGE / "schema" / "flashpoint_indicator.response.json").read_text(encoding="utf-8")
)
ENVELOPE_SCHEMA = json.loads(
    (PACKAGE / "schema" / "envelope.response.json").read_text(encoding="utf-8")
)
ENVELOPE = Draft202012Validator(ENVELOPE_SCHEMA)
RECORD = Draft202012Validator(RESPONSE_SCHEMA)
INPUTS = Draft202012Validator(INPUT_SCHEMA)


def _resolve(_host: str):
    return [ipaddress.ip_address("1.1.1.1")]


def setup_function():
    source._TRANSPORT = None
    source._SLEEPER = None
    source._RNG = None
    source._RESOLVER = _resolve
    source._CACHES.clear()


def _quiet_clock():
    source._SLEEPER = lambda _delay: None
    source._RNG = lambda: 0


def _body() -> bytes:
    return (FIXTURES / "indicator_synthetic.json").read_bytes()


def test_indicator_happy_path_and_schemas(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CYBERAU_FLASHPOINT_SNAPSHOT", str(FIXTURES / "indicator_synthetic.json"))
    found = flashpoint_indicator("Example.COM.au")
    ENVELOPE.validate(found)
    assert found["cache"] == "snapshot"
    assert found["attribution"] == get_vendor("flashpoint").terms.attribution
    assert found["source_urls"] == [INDICATORS_URL]
    assert len(found["data"]) == 1
    row = found["data"][0]
    RECORD.validate(row)
    assert row["value"] == "example.com.au"
    assert row["type"] == "domain"
    assert row["source_ref"] == "synthetic-indicator-1"
    assert row["score"] == "suspicious"
    assert "<<untrusted source=flashpoint>>" in row["summary"]
    assert "Synthetic note" in row["summary"]
    INPUTS.validate({"value": "example.com.au"})
    with pytest.raises(ValidationError):
        INPUTS.validate({"value": "example.com.au", "extra": True})
    with pytest.raises(ValidationError):
        INPUTS.validate({})


def test_empty_malformed_and_short_value(tmp_path, monkeypatch):
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"items": []}), encoding="utf-8")
    monkeypatch.setenv("CYBERAU_FLASHPOINT_SNAPSHOT", str(empty))
    missed = flashpoint_indicator("missing.example.com")
    ENVELOPE.validate(missed)
    assert missed["data"] == []
    assert missed["warnings"]

    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    monkeypatch.setenv("CYBERAU_FLASHPOINT_SNAPSHOT", str(broken))
    warned = flashpoint_indicator("example.com.au")
    assert warned["data"] == []
    assert warned["warnings"]
    assert schema_drift({"note": "no list"})

    other = tmp_path / "other.json"
    other.write_text(
        json.dumps({"items": [{"value": "other.example.com"}]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_FLASHPOINT_SNAPSHOT", str(other))
    assert flashpoint_indicator("example.com.au")["data"] == []
    assert flashpoint_indicator("ab")["warnings"]


def test_untrusted_summary_redacts_secrets(tmp_path, monkeypatch):
    payload = json.loads(_body())
    payload["items"][0]["summary"] = "password=hunter2 cookie=sess-abc"
    path = tmp_path / "note.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("CYBERAU_FLASHPOINT_SNAPSHOT", str(path))
    found = flashpoint_indicator("example.com.au")
    summary = found["data"][0]["summary"]
    assert "hunter2" not in summary
    assert "sess-abc" not in summary
    assert "<<untrusted source=flashpoint>>" in summary
    assert TOKEN not in json.dumps(found)


def test_auth_errors_name_the_env_var(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_FLASHPOINT_SNAPSHOT", raising=False)
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLASHPOINT_API_TOKEN", TOKEN)
    _quiet_clock()
    seen = []

    def unauthorised(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        status = 403 if len(seen) > 1 else 401
        body = (FIXTURES / "flashpoint_401.json").read_bytes()
        return httpx.Response(status, content=body)

    source._TRANSPORT = httpx.MockTransport(unauthorised)
    denied = flashpoint_indicator("example.com.au")
    assert denied["data"] == []
    assert "401" in denied["warnings"][0]
    assert "FLASHPOINT_API_TOKEN" in denied["warnings"][0]
    assert TOKEN not in json.dumps(denied)
    request = seen[0]
    assert str(request.url) == INDICATORS_URL
    assert request.url.query == b""
    assert request.headers["authorization"] == f"Bearer {TOKEN}"

    forbidden = flashpoint_indicator("example.com.au")
    assert "403" in forbidden["warnings"][0]
    assert "FLASHPOINT_API_TOKEN" in forbidden["warnings"][0]
    assert TOKEN not in json.dumps(forbidden)


def test_retry_after_and_timeout_and_redirect(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_FLASHPOINT_SNAPSHOT", raising=False)
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLASHPOINT_API_TOKEN", TOKEN)
    delays = []
    source._SLEEPER = delays.append
    source._RNG = lambda: 0
    calls = {"n": 0}
    body = _body()

    def retry(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "7"}, content=b"{}")
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(retry)
    found = flashpoint_indicator("example.com.au")
    assert found["data"][0]["value"] == "example.com.au"
    assert 7.0 in delays
    assert calls["n"] >= 2

    for item in source._cache()._memory.values():
        item.fetched_at -= 10_000

    def timeout(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    source._TRANSPORT = httpx.MockTransport(timeout)
    source._SLEEPER = lambda _delay: None
    stale = flashpoint_indicator("example.com.au")
    assert stale["cache"] == "stale"
    assert stale["data"][0]["value"] == "example.com.au"

    def redirect(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/stolen"})

    source._TRANSPORT = httpx.MockTransport(redirect)
    source._CACHES.clear()
    refused = flashpoint_indicator("example.com.au")
    assert refused["warnings"]
    assert "evil.example" in refused["warnings"][0]


def test_schema_drift_and_live_health(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_FLASHPOINT_SNAPSHOT", raising=False)
    good = connector().health(live=False, check_schema=True)
    assert good.ok is True
    assert good.detail == "schema ok"
    drifted = tmp_path / "drift.json"
    drifted.write_text(
        json.dumps({"items": [{"indicator_value": "example.com.au"}]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_FLASHPOINT_SNAPSHOT", str(drifted))
    failed = connector().health(live=False, check_schema=True)
    assert failed.ok is False
    assert "value" in failed.detail

    monkeypatch.delenv("CYBERAU_FLASHPOINT_SNAPSHOT", raising=False)
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("FLASHPOINT_API_TOKEN", raising=False)

    def explode(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("live health must not call upstream without a token")

    source._TRANSPORT = httpx.MockTransport(explode)
    missing = connector().health(live=True)
    assert missing.ok is True
    assert missing.detail == "not configured"

    monkeypatch.setenv("FLASHPOINT_API_TOKEN", TOKEN)
    calls = {"n": 0}

    def ok(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        assert str(request.url) == INDICATORS_URL
        return httpx.Response(200, content=_body())

    source._TRANSPORT = httpx.MockTransport(ok)
    _quiet_clock()
    live = connector().health(live=True)
    assert live.ok is True
    assert live.detail == "live ok"
    assert calls["n"] == 1


def test_session_cache_skips_disk_and_history_drops_the_note(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_FLASHPOINT_SNAPSHOT", raising=False)
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLASHPOINT_API_TOKEN", TOKEN)
    _quiet_clock()
    calls = {"n": 0}

    def ok(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, content=_body())

    source._TRANSPORT = httpx.MockTransport(ok)
    first = flashpoint_indicator("example.com.au")
    assert first["cache"] == "miss"
    second = flashpoint_indicator("example.com.au")
    assert second["cache"] == "hit"
    assert calls["n"] == 1
    assert not (tmp_path / "http_cache.sqlite").exists()
    log = (tmp_path / "flashpoint-indicators.jsonl").read_text(encoding="utf-8")
    assert "example.com.au" in log
    assert "Synthetic note" not in log
    assert TOKEN not in log
    for path in tmp_path.rglob("*"):
        if path.is_file() and path.suffix != ".jsonl":
            blob = path.read_bytes()
            assert b"example.com.au" not in blob
            assert TOKEN.encode() not in blob
            assert b"Synthetic note" not in blob


def test_offline_uses_cache_or_snapshot(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.delenv("CYBERAU_FLASHPOINT_SNAPSHOT", raising=False)
    shipped = flashpoint_indicator("example.com.au")
    assert shipped["cache"] == "snapshot"
    assert shipped["data"][0]["source_ref"] == "synthetic-indicator-1"

    monkeypatch.setenv("CYBERAU_FLASHPOINT_SNAPSHOT", str(tmp_path / "missing.json"))
    missing = flashpoint_indicator("example.com.au")
    assert missing["data"] == []
    assert missing["warnings"]


def test_terms_registration_and_no_credential_tool(vcr_config):
    item = connector()
    assert isinstance(item, PremiumConnector)
    assert item.vendor == "flashpoint"
    assert item.terms is not None
    assert item.terms.cache == "session"
    assert item.terms.store == "metadata"
    assert item.terms.stix_export is False
    assert item.terms.share_outside_profile is False
    assert item.terms.redistribution == "forbidden"
    assert item.exposure_for(Watchlist(domains=["example.com.au"]), date(2026, 6, 1)) == []
    assert [tool.name for tool in item.tools] == ["flashpoint_indicator"]

    text = Path(source.__file__).read_text(encoding="utf-8")
    assert text.count("https://api.flashpoint.io/") == 1
    for banned in ("noncommunities", "credential-sighting", "sources/v1", "sources/v2"):
        assert banned not in text

    entry = load_servers()["flashpoint"]
    assert entry["default_enabled"] is False
    assert entry["enabled_by_default"] is False
    assert entry["connector"] == "flashpoint"
    rendered = render_premium_servers(load_servers(), env={"FLASHPOINT_API_TOKEN": "present"})
    assert rendered["flashpoint"]["enabled"] is False
    assert "present" not in json.dumps(rendered["flashpoint"])
    kept = render_premium_servers(
        load_servers(),
        env={"FLASHPOINT_API_TOKEN": "present"},
        user_enabled={"flashpoint": True},
    )
    assert kept["flashpoint"]["enabled"] is True

    allow = yaml.safe_load((REPO / "mcp" / "egress-allowlist.yaml").read_text(encoding="utf-8"))
    assert allow["connectors"]["flashpoint"]["hosts"] == ["api.flashpoint.io"]
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert "docs/connectors/flashpoint.md" in readme
    assert "authorization" in vcr_config["filter_headers"]

    for path in FIXTURES.iterdir():
        fixture = path.read_text(encoding="utf-8").lower()
        assert "hunter2" not in fixture
        assert "bearer " not in fixture
        assert "@" not in fixture


def test_tool_annotations_are_read_only():
    listed = asyncio.run(build_server(connector()).list_tools())
    tools = {tool.name: tool for tool in listed}
    assert set(tools) == {"flashpoint_indicator"}
    encoded = json.dumps(tools["flashpoint_indicator"].inputSchema)
    assert "minLength" in encoded
    annotations = tools["flashpoint_indicator"].annotations
    assert annotations.readOnlyHint is True
    assert annotations.openWorldHint is True
