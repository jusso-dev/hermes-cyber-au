import asyncio
import ipaddress
import json
import logging
from datetime import date
from pathlib import Path
from urllib.parse import unquote_plus

import httpx
import pytest
from cyberau_common.server import build_server
from cyberau_darkowl import source
from cyberau_darkowl.source import (
    connector,
    darkowl_search_watchlist,
    schema_drift,
    sign_request,
)
from cyberau_premium.base import Watchlist
from cyberau_premium.samples import SCHEMA as FINDING_SCHEMA
from cyberau_premium.status import load_servers, render_premium_servers
from jsonschema import Draft202012Validator

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ROOT = Path(__file__).resolve().parents[3]
RESPONSE = json.loads(
    (
        Path(__file__).resolve().parents[1] / "schema" / "darkowl_search_watchlist.response.json"
    ).read_text(encoding="utf-8")
)
VALIDATOR = Draft202012Validator(RESPONSE)
FINDING_VALIDATOR = Draft202012Validator(
    FINDING_SCHEMA,
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
PUBLIC = "public-example"
PRIVATE = "synthetic-private-key"
SYNTHETIC = (FIXTURES / "search_synthetic.json").read_bytes()


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("DARKOWL_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("DARKOWL_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("CYBERAU_DARKOWL_SNAPSHOT", raising=False)
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    source._TRANSPORT = None
    source._SLEEPER = None
    source._RNG = None
    source._RESOLVER = lambda _host: [ipaddress.ip_address("203.0.113.10")]
    source._CACHES.clear()
    yield
    source._TRANSPORT = None
    source._SLEEPER = None
    source._RNG = None
    source._RESOLVER = None
    source._CACHES.clear()


def _keys(monkeypatch):
    monkeypatch.setenv("DARKOWL_PUBLIC_KEY", PUBLIC)
    monkeypatch.setenv("DARKOWL_PRIVATE_KEY", PRIVATE)


def _transport(handler):
    source._TRANSPORT = httpx.MockTransport(handler)
    source._SLEEPER = lambda _seconds: None
    source._RNG = lambda: 0


def test_signature_vector_matches_and_hides_the_private_key():
    vector = json.loads((FIXTURES / "signature_vector.json").read_text(encoding="utf-8"))
    signed = sign_request(
        vector["method"],
        vector["path"],
        vector["date"],
        vector["public_key"],
        vector["private_key"],
    )
    assert signed == vector["authorization"]
    assert vector["private_key"] not in signed
    assert "Authorization:" not in (FIXTURES / "signature_vector.json").read_text(encoding="utf-8")


def test_search_snapshot_wraps_text_and_stores_counts_only(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DARKOWL_SNAPSHOT", str(FIXTURES / "search_synthetic.json"))
    result = darkowl_search_watchlist(["example.com.au"])
    assert result["cache"] == "snapshot"
    assert result["untrusted"] is True
    assert result["attribution"].startswith("Commercial licence")
    assert result["source_urls"] == ["https://api.darkowl.com/api/v1/search"]
    VALIDATOR.validate(result["data"])
    record = result["data"][0]
    assert record["hit_count"] == 2
    assert record["subject_type"] == "domain"
    assert record["first_seen"].startswith("2026-01-15")
    assert record["last_seen"].startswith("2026-06-02")
    assert set(record["source_types"]) == {"forum", "paste", "onion.v3", "unclassified"}
    assert record["source_refs"] == ["synthetic-1", "synthetic-2"]
    assert record["snippet"].startswith("<<untrusted source=darkowl>>")
    assert record["snippet"].endswith("<<end untrusted>>")
    assert "Synthetic forum title" in record["title"]
    assert "Older synthetic paste" not in json.dumps(result)
    blob = (tmp_path / "intel.sqlite").read_bytes()
    assert b"Synthetic forum title" not in blob
    assert b"synthetic mention" not in blob
    assert b"synthetic-1" in blob
    findings = connector().exposure_for(
        Watchlist(domains=["example.com.au"]),
        date(2026, 1, 1),
    )
    dumped = findings[0].model_dump(mode="json", exclude_none=True)
    FINDING_VALIDATOR.validate(dumped)
    assert dumped["kind"] == "dark_web_mention"
    assert dumped["stix_exportable"] is False
    assert dumped["licence_scope"] == "store_metadata"
    assert dumped["counts"] == {"hits": 2}


def test_hostile_fields_are_dropped_and_snippets_are_capped(tmp_path, monkeypatch):
    payload = json.loads(SYNTHETIC)
    payload["results"][0]["snippet"] = (
        "See http://example.onion/path and ada@example.com.au " + ("x" * 500) + "\u202e"
    )
    payload["results"][0]["uri"] = "http://example.onion/path"
    payload["results"][0]["url"] = "http://example.onion/path"
    payload["results"][0]["body"] = "full page http://example.onion/secret"
    payload["results"][0]["emails"] = ["ada@example.com.au"]
    path = tmp_path / "hostile.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("CYBERAU_DARKOWL_SNAPSHOT", str(path))
    result = darkowl_search_watchlist(["example.com.au"])
    blob = json.dumps(result)
    assert "example.onion" not in blob
    assert "ada@example.com.au" not in blob
    assert "full page" not in blob
    assert "[link removed]" in result["data"][0]["snippet"]
    inner = (
        result["data"][0]["snippet"]
        .removeprefix("<<untrusted source=darkowl>> ")
        .removesuffix(" <<end untrusted>>")
    )
    assert len(inner) <= 400
    assert "\u202e" not in blob


def test_empty_malformed_and_short_terms(tmp_path, monkeypatch):
    empty = tmp_path / "empty.json"
    empty.write_text('{"total": 0, "resultCount": 0, "results": []}', encoding="utf-8")
    monkeypatch.setenv("CYBERAU_DARKOWL_SNAPSHOT", str(empty))
    quiet = darkowl_search_watchlist(["example.com.au"])
    assert quiet["data"][0]["hit_count"] == 0
    assert quiet["warnings"] == []
    assert "snippet" not in quiet["data"][0]
    broken = tmp_path / "broken.json"
    broken.write_text('{"total": 1}', encoding="utf-8")
    monkeypatch.setenv("CYBERAU_DARKOWL_SNAPSHOT", str(broken))
    warned = darkowl_search_watchlist(["example.com.au"])
    assert warned["data"] == []
    assert warned["warnings"]
    assert schema_drift({"total": 1})
    skipped = darkowl_search_watchlist(["ab"])
    assert skipped["data"] == []
    assert skipped["warnings"]
    bad_date = darkowl_search_watchlist(["example.com.au"], since="01/06/2026")
    assert bad_date["warnings"]


def test_not_configured_does_not_call_the_network():
    def handler(_request):
        raise AssertionError("network")

    _transport(handler)
    result = darkowl_search_watchlist(["example"])
    assert result["cache"] == "snapshot"
    assert result["data"] == []
    assert "DARKOWL_PUBLIC_KEY" in result["warnings"][0]
    assert "DARKOWL_PRIVATE_KEY" in result["warnings"][0]


@pytest.mark.parametrize("status", [401, 403])
def test_auth_failure_names_the_env_vars(monkeypatch, status):
    _keys(monkeypatch)
    body = (FIXTURES / "darkowl_403.json").read_bytes()

    def handler(_request):
        return httpx.Response(status, content=body)

    _transport(handler)
    result = darkowl_search_watchlist(["example.com.au"])
    assert result["data"] == []
    warning = result["warnings"][0]
    assert "DARKOWL_PUBLIC_KEY" in warning
    assert "DARKOWL_PRIVATE_KEY" in warning
    assert PRIVATE not in json.dumps(result)
    assert "forbidden" not in warning


def test_retry_after_is_honoured(monkeypatch):
    _keys(monkeypatch)
    slept = []
    calls = {"n": 0}

    def handler(_request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "4"}, content=b"{}")
        return httpx.Response(200, content=SYNTHETIC)

    source._TRANSPORT = httpx.MockTransport(handler)
    source._SLEEPER = slept.append
    source._RNG = lambda: 0
    result = darkowl_search_watchlist(["example.com.au"])
    assert slept == [4.0]
    assert result["data"][0]["hit_count"] == 2


def test_timeout_falls_back_to_cache(monkeypatch):
    _keys(monkeypatch)
    calls = {"n": 0}

    def handler(_request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, content=SYNTHETIC)
        raise httpx.TimeoutException("timed out")

    _transport(handler)
    first = darkowl_search_watchlist(["example.com.au"])
    assert first["cache"] == "miss"
    cache = source._session_cache()
    for item in cache._memory.values():
        item.ttl = 1
        item.fetched_at -= 10000
    second = darkowl_search_watchlist(["example.com.au"])
    assert second["cache"] == "stale"
    assert second["data"][0]["hit_count"] == 2
    assert calls["n"] > 1


def test_session_cache_and_offline(monkeypatch):
    _keys(monkeypatch)
    calls = {"n": 0}

    def handler(_request):
        calls["n"] += 1
        return httpx.Response(200, content=SYNTHETIC)

    _transport(handler)
    assert darkowl_search_watchlist(["example.com.au"])["cache"] == "miss"
    assert darkowl_search_watchlist(["example.com.au"])["cache"] == "hit"
    assert calls["n"] == 1
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    cached = darkowl_search_watchlist(["example.com.au"])
    assert cached["cache"] == "hit"
    assert calls["n"] == 1
    source._CACHES.clear()
    missing = darkowl_search_watchlist(["example.com.au"])
    assert missing["data"] == []
    assert any("unavailable" in warning for warning in missing["warnings"])
    assert calls["n"] == 1


def test_redirect_off_allowlist_is_refused(monkeypatch):
    _keys(monkeypatch)
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://evil.example/steal"})

    _transport(handler)
    result = darkowl_search_watchlist(["example.com.au"])
    assert result["data"] == []
    assert "egress refused" in result["warnings"][0]
    assert len(seen) == 1
    assert seen[0].startswith("https://api.darkowl.com/api/v1/search?")
    assert "evil.example" not in seen[0]


def test_signed_request_uses_decoded_path_and_sydney_since(monkeypatch, caplog):
    _keys(monkeypatch)
    seen = []

    def handler(request):
        seen.append(request)
        query = unquote_plus(request.url.query.decode())
        signed = request.url.path + "?" + query
        expected = sign_request("GET", signed, request.headers["Date"], PUBLIC, PRIVATE)
        assert request.headers["Authorization"] == expected
        assert PRIVATE not in request.headers["Authorization"]
        assert request.url.host == "api.darkowl.com"
        return httpx.Response(200, content=b'{"total": 0, "results": []}')

    _transport(handler)
    with caplog.at_level(logging.DEBUG):
        result = darkowl_search_watchlist(["example.com.au"], since="2026-06-01")
    assert result["data"][0]["hit_count"] == 0
    query = unquote_plus(seen[0].url.query.decode())
    assert "from=2026-05-31T14:00:00Z" in query
    assert "sort=-d" not in query
    assert PRIVATE not in caplog.text
    assert PRIVATE not in json.dumps(result)


def test_oldest_probe_uses_nonbody_and_does_not_follow_links(monkeypatch):
    _keys(monkeypatch)
    recent = json.loads(SYNTHETIC)
    recent["total"] = 50
    recent["results"][0]["uri"] = "http://example.onion/path"
    oldest = {
        "total": 50,
        "resultCount": 1,
        "results": [
            {
                "id": "synthetic-old",
                "crawlDate": "2020-01-01T00:00:00Z",
                "groups": ["market"],
                "network": "i2p",
            }
        ],
    }
    queries = []

    def handler(request):
        query = unquote_plus(request.url.query.decode())
        queries.append(query)
        if "sort=-d" in query:
            assert "detail=nonbody" in query
            return httpx.Response(200, json=oldest)
        return httpx.Response(200, json=recent)

    _transport(handler)
    result = darkowl_search_watchlist(["example.com.au"])
    assert result["data"][0]["first_seen"].startswith("2020-01-01")
    assert result["data"][0]["last_seen"].startswith("2026-06-02")
    assert any("sort=-d" in query for query in queries)
    assert "example.onion" not in json.dumps(result)
    assert all("example.onion" not in query for query in queries)


def test_schema_drift_and_live_health(monkeypatch):
    ok = connector().health(live=False, check_schema=True)
    assert ok.ok is True
    assert ok.detail == "schema ok"
    monkeypatch.setenv("CYBERAU_DARKOWL_SNAPSHOT", str(FIXTURES / "search_renamed_field.json"))
    failed = connector().health(live=False, check_schema=True)
    assert failed.ok is False
    assert "schema drift" in failed.detail
    monkeypatch.delenv("CYBERAU_DARKOWL_SNAPSHOT")
    assert connector().health(live=False).detail == "not configured"
    _keys(monkeypatch)
    assert connector().health(live=False).detail == "offline ok"

    def hoot(request):
        assert request.url.path == "/api/v1/test"
        return httpx.Response(200, json={"answer": "hoot"})

    _transport(hoot)
    live = connector().health(live=True)
    assert live.ok is True
    assert live.detail == "live ok"

    def denied(_request):
        return httpx.Response(403, json={"message": "no"})

    _transport(denied)
    refused = connector().health(live=True)
    assert refused.ok is False
    assert "DARKOWL_PRIVATE_KEY" in refused.detail


def test_fresh_install_stays_off_and_update_keeps_enabled():
    env = {"DARKOWL_PUBLIC_KEY": "present", "DARKOWL_PRIVATE_KEY": "present"}
    rendered = render_premium_servers(load_servers(), env=env)
    assert rendered["darkowl"]["enabled"] is False
    assert rendered["darkowl"]["env"]["DARKOWL_PUBLIC_KEY"] == "${DARKOWL_PUBLIC_KEY}"
    assert rendered["darkowl"]["env"]["DARKOWL_PRIVATE_KEY"] == "${DARKOWL_PRIVATE_KEY}"
    assert "present" not in json.dumps(rendered["darkowl"])
    kept = render_premium_servers(load_servers(), env=env, user_enabled={"darkowl": True})
    assert kept["darkowl"]["enabled"] is True


def test_tool_annotations_and_schemas():
    listed = asyncio.run(build_server(connector()).list_tools())
    tool = {item.name: item for item in listed}["darkowl_search_watchlist"]
    assert tool.annotations.readOnlyHint is True
    assert tool.annotations.openWorldHint is True
    assert len(f"mcp__darkowl__{tool.name}") == 38
    schema = json.loads(
        (
            Path(__file__).resolve().parents[1] / "schema" / "darkowl_search_watchlist.input.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    assert schema["required"] == ["terms"]
    assert schema["properties"]["terms"]["maxItems"] == 20
    allowlist = (ROOT / "mcp" / "egress-allowlist.yaml").read_text(encoding="utf-8")
    assert "api.darkowl.com" in allowlist


def test_docs_quote_the_terms_and_readme_links_them():
    docs = (ROOT / "docs" / "connectors" / "darkowl.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Off by default: licence terms" in docs
    assert "Commercial licence. Session cache. Store counts and links only, no snippets." in docs
    assert "State these terms before the first DarkOwl call in a session." in docs
    assert "[docs/connectors/darkowl.md](docs/connectors/darkowl.md)" in readme


def test_cassette_replays_without_an_authorization_header():
    import vcr
    from vcr.serialize import deserialize
    from vcr.serializers import yamlserializer

    path = FIXTURES / "darkowl_search_watchlist.yaml"
    text = path.read_text(encoding="utf-8")
    assert "authorization:" not in text.casefold()
    requests, responses = deserialize(text, yamlserializer)
    assert requests and responses[0]["status"]["code"] == 200
    player = vcr.VCR(record_mode="none")
    with player.use_cassette(str(path)):
        played = httpx.get("https://api.darkowl.com/api/v1/search?q=example.com.au&count=0")
    assert played.status_code == 200
    assert played.json()["total"] == 0


def test_vcr_config_filters_authorization(vcr_config):
    assert "authorization" in vcr_config["filter_headers"]
