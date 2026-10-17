import asyncio
import ipaddress
import json
import time
from datetime import date
from pathlib import Path

import cyberau_upguard.source as source
import httpx
import jsonschema
import pytest
from cyberau_common.server import build_server
from cyberau_premium.base import Watchlist, finding_id
from cyberau_premium.catalog import get_vendor
from cyberau_premium.status import load_servers, render_premium_servers
from cyberau_premium.store import ExposureStore
from cyberau_upguard.source import (
    connector,
    upguard_data_leaks,
    upguard_identity_breaches,
    upguard_typosquats,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SCHEMA = Path(__file__).resolve().parents[1] / "schema"
ROOT = Path(__file__).resolve().parents[3]
SINCE = date(2026, 6, 1)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.delenv("UPGUARD_API_KEY", raising=False)
    monkeypatch.delenv("CYBERAU_UPGUARD_FIXTURES", raising=False)
    monkeypatch.delenv("CYBERAU_UPGUARD_SCHEMA_FIXTURE", raising=False)
    source._TRANSPORT = None
    source._SLEEPER = None
    source._RESOLVER = None
    source._SESSION_CACHE = None
    yield
    source._TRANSPORT = None
    source._SLEEPER = None
    source._RESOLVER = None
    source._SESSION_CACHE = None


def _online(monkeypatch, handler, key="upguard-secret-value", sleeper=None):
    monkeypatch.setenv("UPGUARD_API_KEY", key)
    source._RESOLVER = lambda host: [ipaddress.ip_address("1.1.1.1")]
    source._SLEEPER = sleeper or (lambda _delay: None)
    source._TRANSPORT = httpx.MockTransport(handler)
    return key


def _offline(monkeypatch):
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")


def test_offline_happy_path_attribution_and_untrusted_text(monkeypatch):
    _offline(monkeypatch)
    breaches = upguard_identity_breaches()
    assert breaches["attribution"] == get_vendor("upguard").terms.attribution
    assert breaches["untrusted"] is True
    assert breaches["cache"] == "snapshot"
    own = next(row for row in breaches["data"] if row["domain"] == "example.com.au")
    assert own["identities"] == 2
    assert own["data_classes"] == ["Email addresses", "Passwords"]
    assert "<<untrusted source=upguard>>" in own["breach_name"]
    assert "Synthetic Breach" in own["breach_name"]
    dumped = json.dumps(breaches)
    assert "not-a-person" not in dumped
    assert "Synthetic breach note" not in dumped

    leaks = upguard_data_leaks(statuses=["Disclosed"])
    assert len(leaks["data"]) == 1
    assert leaks["data"][0]["status"] == "Disclosed"
    assert "<<untrusted source=upguard>>" in leaks["data"][0]["description"]
    leaked = json.dumps(leaks)
    assert "do-not-keep" not in leaked
    assert "base64" not in leaked

    typos = upguard_typosquats("example.com.au")
    watched = {row["watched_domain"] for row in typos["data"]}
    assert watched == {"example.com.au"}
    assert "<<untrusted source=upguard>>" in typos["data"][0]["permutation_type"]
    rendered = json.dumps(typos)
    assert "203.0.113.10" not in rendered
    assert "mx.examp1e.example.com.au" not in rendered
    assert "examp1e.example.com.au" in rendered


def test_empty_and_malformed_do_not_raise(monkeypatch):
    def empty(_request):
        body = json.dumps(
            {"breached_identities": [], "breaches": [], "total_results": 0}
        ).encode()
        return httpx.Response(200, content=body)

    _online(monkeypatch, empty)
    result = upguard_identity_breaches()
    assert result["data"] == []
    assert result["warnings"] == []

    def malformed(_request):
        return httpx.Response(200, content=b'{"unexpected": true}')

    source._SESSION_CACHE = None
    source._TRANSPORT = httpx.MockTransport(malformed)
    warned = upguard_identity_breaches()
    assert warned["data"] == []
    assert warned["warnings"]
    assert "schema drift" in warned["warnings"][0]


def test_missing_key_names_the_env_var(monkeypatch):
    called = {"n": 0}

    def handler(_request):
        called["n"] += 1
        return httpx.Response(500, content=b"{}")

    source._TRANSPORT = httpx.MockTransport(handler)
    result = upguard_identity_breaches()
    assert called["n"] == 0
    assert result["cache"] == "snapshot"
    assert "UPGUARD_API_KEY" in result["warnings"][0]
    with pytest.raises(ValueError, match="UPGUARD_API_KEY"):
        connector().exposure_for(Watchlist(domains=["example.com.au"]), SINCE)


@pytest.mark.parametrize("status", [401, 403])
def test_auth_failure_names_the_env_var_and_hides_the_key(monkeypatch, status):
    key = "upguard-secret-value"

    def handler(request):
        assert request.headers["authorization"] == key
        assert not request.headers["authorization"].lower().startswith("bearer")
        body = (FIXTURES / "upguard_403.json").read_bytes()
        return httpx.Response(status, content=body + key.encode())

    _online(monkeypatch, handler, key=key)
    result = upguard_identity_breaches()
    dumped = json.dumps(result)
    assert key not in dumped
    assert "UPGUARD_API_KEY" in result["warnings"][0]
    assert str(status) in result["warnings"][0]


def test_429_honours_retry_after(monkeypatch):
    slept = []
    body = (FIXTURES / "breaches_synthetic.json").read_bytes()
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        assert request.url.params["sort_by"] == "date_last_breach"
        assert request.url.params["sort_desc"] == "true"
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "0"}, content=b"{}")
        return httpx.Response(200, content=body)

    _online(monkeypatch, handler, sleeper=slept.append)
    result = upguard_identity_breaches()
    assert calls["n"] == 2
    assert slept == [0.0]
    assert result["data"][0]["domain"] == "example.com.au"


def test_timeout_falls_back_to_session_cache(monkeypatch):
    body = (FIXTURES / "breaches_synthetic.json").read_bytes()
    calls = {"n": 0}

    def handler(_request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, content=body)
        raise httpx.TimeoutException("timed out")

    _online(monkeypatch, handler)
    first = upguard_identity_breaches()
    assert first["data"]
    assert not (Path(source._data_dir()) / "upguard-session.sqlite").exists()
    item = next(iter(source._SESSION_CACHE._memory.values()))
    item.fetched_at = time.time() - item.ttl - 5
    second = upguard_identity_breaches()
    assert second["cache"] == "stale"
    assert second["data"][0]["breach_id"] == "101"
    assert calls["n"] > 1


def test_schema_drift_fails_health(monkeypatch, tmp_path):
    assert connector().health(live=False, check_schema=True).ok is True
    payload = json.loads((FIXTURES / "breaches_synthetic.json").read_text(encoding="utf-8"))
    payload["identities"] = payload.pop("breached_identities")
    path = tmp_path / "drift.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("CYBERAU_UPGUARD_SCHEMA_FIXTURE", str(path))
    probe = connector().health(live=False, check_schema=True)
    assert probe.ok is False
    assert "breached_identities" in probe.detail


def test_redirect_is_refused(monkeypatch):
    key = "upguard-secret-value"

    def handler(_request):
        return httpx.Response(302, headers={"location": "https://denied.example/stolen"})

    _online(monkeypatch, handler, key=key)
    result = upguard_typosquats("example.com.au")
    assert result["data"] == []
    assert "allowlisted" in result["warnings"][0]
    assert key not in json.dumps(result)


def test_domain_not_enabled(monkeypatch):
    body = (FIXTURES / "upguard_404_domain_not_enabled.json").read_bytes()

    def handler(request):
        assert request.url.params["domain"] == "example.com.au"
        return httpx.Response(404, content=body)

    _online(monkeypatch, handler)
    result = upguard_typosquats("example.com.au")
    assert result["data"] == []
    assert "not enabled" in result["warnings"][0]


def test_typosquat_finding_records_the_watched_domain(monkeypatch, tmp_path):
    _offline(monkeypatch)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    watch = Watchlist(domains=["example.com.au"])
    findings = connector().exposure_for(watch, SINCE)
    typos = [item for item in findings if item.kind == "typosquat_domain"]
    assert len(typos) == 1
    finding = typos[0]
    assert finding.subject.value == "example.com.au"
    assert finding.subject.watchlist_entry == "example.com.au"
    assert finding.source_ref == "examp1e.example.com.au"
    assert finding.finding_id == finding_id(
        "upguard",
        "typosquat_domain",
        "example.com.au",
        "examp1e.example.com.au",
    )
    assert finding.stix_exportable is False
    assert finding.licence_scope == "store_metadata"
    hosts = {item.source_ref for item in typos}
    assert "old.example.com.au" not in hosts
    assert "example-login.example.com.au" not in hosts
    assert all(item.subject.value != "other.example.au" for item in findings)
    store = ExposureStore(tmp_path / "intel.sqlite")
    row = store.get(finding.finding_id)
    assert row["subject_value"] == "example.com.au"
    assert row["source_ref"] == "examp1e.example.com.au"
    blob = (tmp_path / "intel.sqlite").read_bytes()
    assert b"not-a-person" not in blob
    assert b"do-not-keep" not in blob
    assert b"203.0.113.10" not in blob
    assert b"other.example.au" not in blob


def test_data_leak_window_and_filters(monkeypatch):
    _offline(monkeypatch)
    window = upguard_data_leaks(since="2026-06-01T00:00:00Z", until="2026-06-03T00:00:00Z")
    assert [row["id"] for row in window["data"]] == ["3426"]
    assert upguard_data_leaks(statuses=["ClosedNoIssue"])["data"][0]["id"] == "100"
    assert upguard_data_leaks(since="yesterday")["warnings"]
    assert upguard_data_leaks(statuses=["Pwned"])["warnings"]
    assert upguard_typosquats("not a domain")["warnings"]
    assert upguard_identity_breaches(limit=0)["warnings"]


def test_session_cache_is_not_on_disk_and_typosquats_are(monkeypatch):
    def handler(request):
        if request.url.path.endswith("/breaches"):
            return httpx.Response(200, content=(FIXTURES / "breaches_synthetic.json").read_bytes())
        if request.url.path.endswith("/typosquat/details"):
            body = (FIXTURES / "typosquat_details_synthetic.json").read_bytes()
            return httpx.Response(200, content=body)
        return httpx.Response(200, json={"domains": []})

    _online(monkeypatch, handler)
    upguard_identity_breaches()
    directory = source._data_dir()
    assert not (directory / "upguard-session.sqlite").exists()
    upguard_typosquats("example.com.au")
    assert (directory / "upguard-ttl.sqlite").exists()
    assert not (directory / "upguard-session.sqlite").exists()


def test_live_health_and_tool_annotations():
    listed = asyncio.run(build_server(connector()).list_tools())
    tools = {tool.name: tool for tool in listed}
    for name in ("upguard_identity_breaches", "upguard_data_leaks", "upguard_typosquats"):
        file_schema = json.loads((SCHEMA / f"{name}.input.json").read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(file_schema)
        generated = tools[name].inputSchema
        for prop in file_schema["properties"]:
            assert prop in generated["properties"]
        assert tools[name].annotations.readOnlyHint is True
        assert tools[name].annotations.openWorldHint is True
        assert len(f"mcp__upguard__{name}") <= 64
    assert "Commercial licence" in tools["upguard_typosquats"].description


def test_live_health_uses_one_get(monkeypatch):
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        assert request.method == "GET"
        assert request.url.path == "/api/public/typosquat"
        return httpx.Response(
            200,
            json={"domains": [{"domain": "example.com.au", "num_registered": 1}]},
        )

    _online(monkeypatch, handler)
    probe = connector().health(live=True)
    assert probe.ok is True
    assert probe.detail == "live ok"
    assert calls["n"] == 1

    def denied(_request):
        return httpx.Response(403, content=(FIXTURES / "upguard_403.json").read_bytes())

    source._TRANSPORT = httpx.MockTransport(denied)
    failed = connector().health(live=True)
    assert failed.ok is False
    assert "UPGUARD_API_KEY" in failed.detail


def test_fresh_install_stays_disabled_and_update_keeps_enabled():
    entry = load_servers()["upguard"]
    assert entry["default_enabled"] is False
    assert entry["enabled_by_default"] is False
    rendered = render_premium_servers(load_servers(), env={"UPGUARD_API_KEY": "present"})
    assert rendered["upguard"]["enabled"] is False
    assert "present" not in json.dumps(rendered["upguard"])
    kept = render_premium_servers(
        load_servers(),
        env={"UPGUARD_API_KEY": "present"},
        user_enabled={"upguard": True},
    )
    assert kept["upguard"]["enabled"] is True
    assert kept["flare"]["enabled"] is False


def test_docs_quote_terms_and_readme_links_them():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "[docs/connectors/upguard.md](docs/connectors/upguard.md)" in readme
    page = (ROOT / "docs" / "connectors" / "upguard.md").read_text(encoding="utf-8")
    attribution = get_vendor("upguard").terms.attribution
    assert attribution in page
    assert "UPGUARD_API_KEY" in page
    assert "\u2014" not in page
    assert "\u2013" not in page
    source_text = Path(source.__file__).read_text(encoding="utf-8")
    assert ".put(" not in source_text
    assert ".post_" not in source_text


def test_cassettes_replay_without_secrets(vcr_config):
    import vcr

    assert "authorization" in vcr_config["filter_headers"]
    uris = {
        "upguard_identity_breaches": (
            "https://cyber-risk.upguard.com/api/public/breaches"
            "?page_size=10&sort_by=date_last_breach&sort_desc=true"
        ),
        "upguard_data_leaks": "https://cyber-risk.upguard.com/api/public/dataleaks/disclosures",
        "upguard_typosquats": (
            "https://cyber-risk.upguard.com/api/public/typosquat/details?domain=example.com.au"
        ),
    }
    player = vcr.VCR(record_mode="none")
    for name, uri in uris.items():
        path = FIXTURES / f"{name}.yaml"
        text = path.read_text(encoding="utf-8")
        assert "upguard-secret-value" not in text
        assert "Authorization:" not in text
        with player.use_cassette(str(path)):
            played = httpx.get(uri)
        assert played.status_code == 200
