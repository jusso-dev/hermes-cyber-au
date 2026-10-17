import asyncio
import ipaddress
import json
import os
import time
from pathlib import Path

import cyberau_asd_blueprint.source as source
import httpx
import jsonschema
from cyberau_asd_blueprint.source import (
    ORIGIN,
    blueprint_search,
    connector,
    parse_html,
    refresh_index,
    schema_drift,
)
from cyberau_common.cache import HttpCache
from cyberau_common.server import build_server

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SCHEMA = Path(__file__).resolve().parents[1] / "schema"
ENVELOPE = {
    "type": "object",
    "required": ["source", "retrieved_at", "cache", "data", "untrusted", "attribution"],
    "properties": {
        "cache": {"enum": ["hit", "miss", "stale", "snapshot"]},
        "untrusted": {"const": True},
        "attribution": {"type": "string"},
        "data": {},
        "warnings": {"type": "array"},
    },
}


def setup_function():
    os.environ["CYBERAU_OFFLINE"] = "1"
    os.environ["CYBERAU_BLUEPRINT_SNAPSHOT"] = str(FIXTURES / "blueprint_two_pages.json")
    source._TRANSPORT = None
    source._SLEEP = time.sleep
    source._CLOCK = time.monotonic
    source._RESOLVER = None


def _public(_host: str):
    return [ipaddress.ip_address("1.1.1.1")]


def _row(result: dict, item: str) -> dict:
    found = [row for row in result["data"] if item in row["item"]]
    assert found, result["data"]
    return found[0]


def test_search_returns_setting_and_link(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    found = blueprint_search("require multifactor")
    jsonschema.validate(found, ENVELOPE)
    assert found["cache"] == "snapshot"
    assert found["source"] == "asd-blueprint"
    assert "not an ASD assessment" in found["attribution"]
    assert "not endorsed by ASD" in found["attribution"]
    row = _row(found, "Require multifactor authentication")
    assert row["url"].endswith("/limit-admin-sessions/")
    assert row["url"].startswith("https://blueprint.asd.gov.au/")
    assert "<<untrusted" not in row["url"]
    assert "<<untrusted source=asd-blueprint>>" in row["title"]
    assert "<<untrusted source=asd-blueprint>>" in row["item"]
    assert "<<untrusted source=asd-blueprint>>" in row["value"]
    assert "Not checked" in row["value"]
    record_schema = json.loads((SCHEMA / "blueprint_search.response.json").read_text())
    jsonschema.validate(
        {key: row[key] for key in ("url", "title", "section", "group", "item", "value")},
        record_schema,
    )
    input_schema = json.loads((SCHEMA / "blueprint_search.input.json").read_text())
    jsonschema.validate({"query": "require multifactor"}, input_schema)
    saved = (tmp_path / "blueprint-observations.jsonl").read_text(encoding="utf-8")
    assert "limit-admin-sessions" in saved
    assert "super-secret" not in saved

    passwords = blueprint_search("app passwords")
    password = _row(passwords, "app passwords")
    assert password["url"].endswith("/per-user-mfa/")
    assert "Do not allow" in password["value"]


def test_empty_malformed_and_drift():
    missing = blueprint_search("zzzz-not-a-setting")
    assert missing["data"] == []
    assert missing["warnings"]
    assert missing["cache"] == "snapshot"
    assert "not endorsed by ASD" in missing["attribution"]
    assert blueprint_search("a")["warnings"]

    os.environ["CYBERAU_BLUEPRINT_SNAPSHOT"] = str(FIXTURES / "blueprint_malformed.json")
    broken = blueprint_search("multifactor")
    assert broken["data"] == []
    assert broken["warnings"]
    assert any("JSON" in warning for warning in broken["warnings"])

    os.environ["CYBERAU_BLUEPRINT_SNAPSHOT"] = str(FIXTURES / "blueprint_drift.json")
    assert schema_drift(json.loads((FIXTURES / "blueprint_drift.json").read_text()))
    drifted = blueprint_search("multifactor")
    assert drifted["data"] == []
    assert any("schema drift" in warning for warning in drifted["warnings"])
    probe = connector().health(live=False, check_schema=True)
    assert probe.ok is False
    assert "schema drift" in probe.detail

    os.environ["CYBERAU_BLUEPRINT_SNAPSHOT"] = str(FIXTURES / "blueprint_two_pages.json")
    assert connector().health(live=False, check_schema=True).ok is True
    assert schema_drift({"pages": []}) is None


def test_bidi_is_stripped_and_page_query_returns_a_link(tmp_path):
    payload = json.loads((FIXTURES / "blueprint_two_pages.json").read_text(encoding="utf-8"))
    payload["pages"][1]["settings"][0]["value"] = "allow\u202e hidden"
    path = tmp_path / "marked.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    os.environ["CYBERAU_BLUEPRINT_SNAPSHOT"] = str(path)
    found = blueprint_search("app passwords")
    value = _row(found, "app passwords")["value"]
    assert "\u202e" not in value
    assert "<<untrusted source=asd-blueprint>>" in value

    os.environ["CYBERAU_BLUEPRINT_SNAPSHOT"] = str(FIXTURES / "blueprint_two_pages.json")
    page = blueprint_search("per-user mfa")
    assert page["data"]
    assert page["data"][0]["url"].endswith("/per-user-mfa/")


def test_parser_skips_header_and_keeps_link_text():
    html = """
    <html><article>
      <h2>Synthetic control</h2>
      <p>Synthetic summary.</p>
      <h3>Session</h3>
      <table>
        <tr><th>Item</th><th>Value</th></tr>
        <tr><td>Sign-in frequency</td><td>4 hours <a href="/x">link</a></td></tr>
      </table>
    </article></html>
    """
    page = parse_html(
        html,
        "https://blueprint.asd.gov.au/configuration/entra-id/users/per-user-mfa/",
    )
    assert page["title"] == "Synthetic control"
    assert page["settings"] == [
        {"group": "Session", "item": "Sign-in frequency", "value": "4 hours link"}
    ]
    assert "Entra ID" in page["section"]
    assert schema_drift({"pages": [page]}) is None
    assert parse_html("<html>nope", "https://blueprint.asd.gov.au/")["title"] == ""


def test_advertised_schema_and_model_name():
    tools = {tool.name: tool for tool in asyncio.run(build_server(connector()).list_tools())}
    encoded = json.dumps(tools["blueprint_search"].inputSchema)
    assert "minLength" in encoded
    model_name = "mcp__blueprint__blueprint_search"
    assert len(model_name) == 32
    assert tools["blueprint_search"].annotations.readOnlyHint is True


def test_offline_index_is_stale_and_fresh_index_is_a_hit(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("CYBERAU_BLUEPRINT_SNAPSHOT", raising=False)
    index = json.loads((FIXTURES / "blueprint_two_pages.json").read_text(encoding="utf-8"))
    index["retrieved_at"] = "2000-01-01T00:00:00Z"
    (tmp_path / "blueprint-index.json").write_text(json.dumps(index), encoding="utf-8")
    stale = blueprint_search("enable policy")
    assert stale["cache"] == "stale"
    assert "On" in _row(stale, "Enable policy")["value"]

    index["retrieved_at"] = source._now()
    (tmp_path / "blueprint-index.json").write_text(json.dumps(index), encoding="utf-8")
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    fresh = blueprint_search("enable policy")
    assert fresh["cache"] == "hit"


def test_auth_refusal_retry_after_timeout_and_redirect(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.delenv("CYBERAU_BLUEPRINT_SNAPSHOT", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    source._RESOLVER = _public
    clock = {"t": 1_000.0}
    slept: list[float] = []

    def now() -> float:
        return clock["t"]

    def sleeper(seconds: float) -> None:
        slept.append(seconds)
        clock["t"] += seconds

    source._CLOCK = now
    source._SLEEP = sleeper

    def denied(status: int):
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(status, content=b"nope")

        return handler

    try:
        source._TRANSPORT = httpx.MockTransport(denied(401))
        unauthorised = connector().health(live=True)
        assert unauthorised.ok is False
        assert "401" in unauthorised.detail
        assert "environment variable" in unauthorised.detail

        source._TRANSPORT = httpx.MockTransport(denied(403))
        forbidden = connector().health(live=True)
        assert forbidden.ok is False
        assert "403" in forbidden.detail
        assert "environment variable" in forbidden.detail

        calls = {"n": 0}

        def retry(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(429, headers={"retry-after": "7"}, content=b"slow")
            assert str(request.url).rstrip("/") == ORIGIN.rstrip("/")
            body = b"<html><title>ASD's Blueprint for Secure Cloud</title></html>"
            return httpx.Response(200, content=body)

        slept.clear()
        source._TRANSPORT = httpx.MockTransport(retry)
        live = connector().health(live=True)
        assert live.ok is True
        assert 7.0 in slept

        cache = HttpCache(tmp_path / "timeout" / "http_cache.sqlite")
        cached = b"<html><article><h2>Cached Blueprint for Secure Cloud</h2></article></html>"
        key = cache.key("GET", ORIGIN, None, b"", "anonymous")
        cache.put(key, status=200, headers={}, body=cached, ttl=0)
        monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "timeout"))

        def boom(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("timed out")

        source._TRANSPORT = httpx.MockTransport(boom)
        text, state, _warning = source._fetch(ORIGIN)
        assert state == "stale"
        assert text is not None and "Cached Blueprint" in text

        def redirect(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"location": "https://evil.test/x"})

        monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "redirect"))
        source._TRANSPORT = httpx.MockTransport(redirect)
        refused = connector().health(live=True)
        assert refused.ok is False
        assert "not allowlisted" in refused.detail
    finally:
        source._TRANSPORT = None
        source._SLEEP = time.sleep
        source._CLOCK = time.monotonic
        source._RESOLVER = None


def test_refresh_paces_pages_and_search_reads_the_index(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CYBERAU_BLUEPRINT_SNAPSHOT", str(FIXTURES / "blueprint_two_pages.json"))
    source._RESOLVER = _public
    clock = {"t": 1_000.0}
    slept: list[float] = []

    def now() -> float:
        return clock["t"]

    def sleeper(seconds: float) -> None:
        slept.append(seconds)
        clock["t"] += seconds

    source._CLOCK = now
    source._SLEEP = sleeper

    def page(request: httpx.Request) -> httpx.Response:
        if "per-user-mfa" in str(request.url):
            title, item, value = "Per-user MFA", "app passwords", "Do not allow"
        else:
            title, item, value = (
                "ADM - S - Limit admin sessions",
                "Require multifactor authentication",
                "Not checked",
            )
        html = (
            "<html><article><h2>"
            + title
            + "</h2><p>Synthetic.</p><h3>Controls</h3><table>"
            + "<tr><th>Item</th><th>Value</th></tr><tr><td>"
            + item
            + "</td><td>"
            + value
            + "</td></tr></table></article></html>"
        )
        return httpx.Response(200, content=html.encode())

    source._TRANSPORT = httpx.MockTransport(page)
    try:
        refreshed = refresh_index()
    finally:
        source._TRANSPORT = None
        source._SLEEP = time.sleep
        source._CLOCK = time.monotonic
        source._RESOLVER = None
    assert refreshed["cache"] == "miss"
    assert "not endorsed by ASD" in refreshed["attribution"]
    assert any(seconds >= 4 for seconds in slept)
    monkeypatch.delenv("CYBERAU_BLUEPRINT_SNAPSHOT", raising=False)
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    found = blueprint_search("app passwords")
    assert found["cache"] == "stale"
    assert _row(found, "app passwords")["url"].endswith("/per-user-mfa/")


def test_offline_refresh_skips_the_network():
    skipped = refresh_index()
    assert skipped["cache"] == "snapshot"
    assert skipped["warnings"]


def test_cassette_replays_homepage():
    import vcr

    player = vcr.VCR(record_mode="none")
    path = FIXTURES / "blueprint_search.yaml"
    with player.use_cassette(str(path)):
        played = httpx.get(ORIGIN)
    assert played.status_code == 200
    assert "Blueprint for Secure Cloud" in played.text
