"""Offline tests for the Flare connector. Fixtures are synthetic."""

from __future__ import annotations

import asyncio
import json
import shutil
from datetime import date
from pathlib import Path

import httpx
from cyberau_common.server import build_server
from cyberau_flare import client as flare_client
from cyberau_flare.client import (
    TOKEN_TTL_S,
    domain_query,
    fetch_tenant_events,
)
from cyberau_flare.quota import global_search_decision, quota_view, record_global_search
from cyberau_flare.source import (
    READ_TOOLS,
    TERMS_NOTICE,
    WRITE_TOOLS,
    Watchlist,
    _search_body,
    aggregate_credentials,
    allowed_mcp_tools,
    connector,
    flare_domain_credentials,
    flare_identifier_events,
    flare_identifiers,
    flare_quota_status,
    flare_tenant_exposure,
    load_mcp_tool_names,
    mcp_drift,
    premium_doctor_lines,
    render_mcp_entry,
)
from cyberau_premium.catalog import get_vendor
from cyberau_premium.status import load_servers, render_premium_servers
from cyberau_premium.store import ExposureStore
from jsonschema import Draft202012Validator

FIXTURES = Path(__file__).resolve().parent / "fixtures"
REPO = Path(__file__).resolve().parents[3]
SCHEMA = REPO / "mcp" / "flare" / "schema"
KEY = "unit-test-flare-key"
TOKEN = "synthetic-flare-token"


def _use_fixtures(monkeypatch, directory: Path | None = None) -> None:
    monkeypatch.setenv("CYBERAU_FLARE_FIXTURES", str(directory or FIXTURES))
    monkeypatch.delenv("CYBERAU_FLARE_HTTP", raising=False)


def _use_http(monkeypatch) -> None:
    monkeypatch.setenv("CYBERAU_FLARE_HTTP", "1")
    monkeypatch.delenv("CYBERAU_FLARE_FIXTURES", raising=False)


def _clock():
    state = {"t": 1_000_000.0}
    sleeps: list[float] = []

    def clock() -> float:
        return state["t"]

    def sleeper(seconds: float) -> None:
        sleeps.append(float(seconds))
        state["t"] += float(seconds)

    flare_client.CLOCK = clock
    flare_client.SLEEPER = sleeper
    return state, sleeps


def _watchlist(tmp_path: Path) -> None:
    (tmp_path / "org-exposure.yaml").write_text(
        "organisation: Example Pty Ltd\n"
        "domains:\n"
        "  - example.com.au\n"
        "  - example.au\n"
        "email_domains:\n"
        "  - example.com.au\n"
        "brands:\n"
        "  - Example\n",
        encoding="utf-8",
    )


def _validate(tool: str, payload: dict) -> None:
    schema = json.loads((SCHEMA / f"{tool}.response.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(payload)


def test_tenant_exposure_maps_kinds_and_wraps_text(monkeypatch, tmp_path):
    _use_fixtures(monkeypatch)
    _watchlist(tmp_path)
    result = flare_tenant_exposure(since="2026-06-01")
    _validate("flare_tenant_exposure", result)
    assert result["attribution"] == get_vendor("flare").terms.attribution
    assert result["untrusted"] is True
    kinds = {row["event_type"]: row["kind"] for row in result["data"]}
    assert kinds["stealer_log"] == "infostealer_credential"
    assert kinds["ransomleak"] == "leak_site_claim"
    assert kinds["leak"] == "leak_site_claim"
    assert "chat_message" not in kinds
    assert "listing/synthetic/old" not in json.dumps(result["data"])
    ransom = next(row for row in result["data"] if row["event_type"] == "ransomleak")
    assert ransom["confidence"] == "vendor_reported"
    assert "unconfirmed" in ransom["briefing"]
    assert "<<untrusted source=flare>>" in ransom["summary"]
    assert "password" not in json.dumps(result["data"])
    high = flare_tenant_exposure(since="2026-06-01", min_severity="high")
    assert {row["event_type"] for row in high["data"]} == {"stealer_log", "ransomleak"}


def test_exposure_for_watchlist_end_to_end(monkeypatch, tmp_path):
    _use_fixtures(monkeypatch)
    _watchlist(tmp_path)
    findings = connector().exposure_for(Watchlist.model_validate(yaml_watch()), date(2026, 6, 1))
    kinds = sorted(item.kind for item in findings)
    assert kinds == ["infostealer_credential", "leak_site_claim", "leak_site_claim"]
    assert all(item.vendor == "flare" for item in findings)
    assert all(item.stix_exportable is False for item in findings)
    store = ExposureStore(tmp_path / "intel.sqlite")
    stored = [store.get(item.finding_id) for item in findings]
    assert all(row is not None for row in stored)
    ransom = next(item for item in findings if item.source_ref.startswith("ransomleak"))
    assert store.get(ransom.finding_id)["confidence"] == "unverified_claim"
    blob = (tmp_path / "intel.sqlite").read_bytes()
    assert b"hunter2" not in blob
    assert TOKEN.encode() not in blob


def yaml_watch() -> dict:
    return {
        "domains": ["example.com.au", "example.au"],
        "email_domains": ["example.com.au"],
        "brands": ["Example"],
    }


def test_identifier_events_identifiers_and_credentials(monkeypatch, tmp_path):
    _use_fixtures(monkeypatch)
    _watchlist(tmp_path)
    events = flare_identifier_events(101, since="2026-06-01")
    _validate("flare_identifier_events", events)
    assert events["data"][0]["event_type"] == "stealer_log"
    listed = flare_identifiers()
    _validate("flare_identifiers", listed)
    assert "example.au" in listed["data"]["missing_from_flare"]
    assert "extra.example.com.au" in listed["data"]["not_on_watchlist"]
    assert "<<untrusted source=flare>>" in listed["data"]["identifiers"][0]["name"]
    lines = premium_doctor_lines(
        Watchlist.model_validate(yaml_watch()),
        json.loads((FIXTURES / "identifiers_synthetic.json").read_text())["items"],
    )
    assert lines == [
        "flare: watchlist entry Example is not monitored",
        "flare: watchlist entry example.au is not monitored",
    ]
    counts = flare_domain_credentials("example.com.au", since="2026-06-01")
    _validate("flare_domain_credentials", counts)
    assert counts["data"] == [
        {"source_type": "combolists", "imported_on": "2026-06-02", "count": 2}
    ]
    poisoned = aggregate_credentials(
        [
            {
                "imported_at": "2026-06-02T03:04:05+00:00",
                "source_id": "combolists",
                "hash": "not-a-real-secret",
                "identity_name": "ada@example.com.au",
            }
        ],
        since="2026-06-01",
    )
    blob = json.dumps(poisoned)
    assert "not-a-real-secret" not in blob
    assert "ada@example.com.au" not in blob
    status = flare_quota_status()
    _validate("flare_quota_status", status)
    assert status["data"]["remaining"] is None
    assert status["warnings"]


def test_empty_and_malformed_payloads(monkeypatch, tmp_path):
    _use_fixtures(monkeypatch, _copy(tmp_path, {"items": [], "next": None}))
    empty = flare_tenant_exposure(since="2026-06-01")
    assert empty["data"] == []
    assert empty["warnings"] == []
    _use_fixtures(monkeypatch, _copy(tmp_path, "{"))
    broken = flare_tenant_exposure(since="2026-06-01")
    assert broken["data"] == []
    assert "not usable" in broken["warnings"][0]


def _copy(tmp_path: Path, tenant) -> Path:
    dest = tmp_path / "fixtures"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(FIXTURES, dest)
    text = tenant if isinstance(tenant, str) else json.dumps(tenant)
    (dest / "tenant_events_synthetic.json").write_text(text, encoding="utf-8")
    return dest


def test_missing_key_names_the_env_var(monkeypatch):
    monkeypatch.delenv("FLARE_API_KEY")
    result = flare_tenant_exposure(since="2026-06-01")
    assert "FLARE_API_KEY" in result["warnings"][0]
    assert KEY not in result["warnings"][0]
    assert connector().health_result().detail == "not configured"


def test_input_schema_rejects_email_password_and_bad_limit():
    bad_domain = flare_domain_credentials("ada@example.com.au")
    assert bad_domain["warnings"]
    assert bad_domain["data"] == []
    assert flare_tenant_exposure(limit=0)["warnings"]
    body = domain_query("example.com.au", since=None, size=100)
    assert body["query"] == {"type": "domain", "fqdn": "example.com.au"}
    assert "password" not in json.dumps(body)
    assert "email" not in json.dumps(body)
    hidden = _search_body(None, ["stealer_log"], None, remediated=False)
    assert hidden["filters"]["is_remediated"] is False
    shown = _search_body(None, ["stealer_log"], None, remediated=None)
    assert "is_remediated" not in shown["filters"]
    client_text = Path(flare_client.__file__).read_text(encoding="utf-8")
    assert "identifiers_create" not in client_text


def test_tools_are_read_only():
    listed = asyncio.run(build_server(connector()).list_tools())
    tools = {tool.name: tool for tool in listed}
    assert set(tools) == {
        "flare_tenant_exposure",
        "flare_identifier_events",
        "flare_identifiers",
        "flare_domain_credentials",
        "flare_quota_status",
    }
    for tool in tools.values():
        assert tool.annotations.readOnlyHint is True
        assert tool.annotations.openWorldHint is True
    props = tools["flare_domain_credentials"].inputSchema["properties"]
    assert set(props) == {"domain", "since"}


def test_schema_drift_and_mcp_filter(monkeypatch, tmp_path):
    assert connector().health(live=False, check_schema=True).ok is True
    path = tmp_path / "drift.json"
    path.write_text(json.dumps({"items": [{"meta": {}}]}), encoding="utf-8")
    monkeypatch.setenv("CYBERAU_FLARE_SCHEMA_FIXTURE", str(path))
    failed = connector().health(live=False, check_schema=True)
    assert failed.ok is False
    assert "metadata" in failed.detail
    names = load_mcp_tool_names()
    assert allowed_mcp_tools(names) == list(READ_TOOLS)
    for name in WRITE_TOOLS:
        assert name not in allowed_mcp_tools(names)
    assert mcp_drift(["search_tenant", "events_brand_new"])
    entry = load_servers()["flare_mcp"]
    rendered = render_mcp_entry(entry)
    assert rendered["enabled"] is False
    assert rendered["trust"] == "untrusted"
    assert rendered["url"] == "https://api.flare.io/mcp"
    assert rendered["tools"]["include"] == list(READ_TOOLS)


def test_ships_disabled_and_update_keeps_enabled():
    env = {"FLARE_API_KEY": "present", "FLARE_TENANT_ID": "present"}
    fresh = render_premium_servers(load_servers(), env=env)
    assert fresh["flare"]["enabled"] is False
    assert "present" not in json.dumps(fresh["flare"])
    assert "flare_mcp" not in fresh
    kept = render_premium_servers(load_servers(), env=env, user_enabled={"flare": True})
    assert kept["flare"]["enabled"] is True


def test_docs_quote_the_terms_and_readme_links():
    docs = (REPO / "docs" / "connectors" / "flare.md").read_text(encoding="utf-8")
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert "off by default: licence terms" in docs
    assert TERMS_NOTICE.split(". ")[0] in docs
    assert "\u2014" not in docs
    assert "docs/connectors/flare.md" in readme


def test_cassettes_redact_the_key(vcr_config):
    text = (Path(__file__).parent / "cassettes" / "token_generate.yaml").read_text(encoding="utf-8")
    assert "authorization" in vcr_config["filter_headers"]
    assert "REDACTED" in text
    assert KEY not in text
    assert TOKEN not in text


def test_secrets_are_scrubbed_and_token_refreshes(monkeypatch, caplog):
    _use_http(monkeypatch)
    state, _sleeps = _clock()
    issued: list[str] = []
    auths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/tokens/generate":
            assert request.headers["authorization"] == KEY
            token = f"{TOKEN}-{len(issued) + 1}"
            issued.append(token)
            return httpx.Response(200, json={"token": token, "refresh_token_exp": 1})
        auths.append(request.headers["authorization"])
        if len(auths) == 1:
            return httpx.Response(
                401, json={"error": {"code": "UNAUTHORIZED", "message": "rejected"}}
            )
        return httpx.Response(200, json={"items": [], "next": None})

    flare_client.TRANSPORT = httpx.MockTransport(handler)
    with caplog.at_level("DEBUG", logger="cyberau.flare"):
        result = flare_tenant_exposure(since="2026-06-01")
    assert result["warnings"] == []
    assert auths[-1] == f"Bearer {TOKEN}-2"
    assert len(issued) == 2
    start = state["t"]
    fetch_tenant_events({"filters": {"type": ["listing"]}}, limit=5)
    state["t"] = start + TOKEN_TTL_S - 30
    fetch_tenant_events({"filters": {"type": ["leak"]}}, limit=5)
    assert len(issued) >= 3
    blob = caplog.text + json.dumps(result)
    assert KEY not in blob
    assert TOKEN not in blob


def test_rate_limit_wait_and_retry_after(monkeypatch):
    _use_http(monkeypatch)

    def run(header: str | None) -> list[float]:
        flare_client.reset_token()
        _state, sleeps = _clock()
        seen = {"limited": False}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/tokens/generate":
                return httpx.Response(200, json={"token": TOKEN, "refresh_token_exp": 1})
            if not seen["limited"]:
                seen["limited"] = True
                headers = {"Retry-After": header} if header else {}
                payload = json.loads(
                    (FIXTURES / "flare_429_ratelimit.json").read_text(encoding="utf-8")
                )
                return httpx.Response(429, json=payload, headers=headers)
            return httpx.Response(200, json={"items": [], "next": None})

        flare_client.TRANSPORT = httpx.MockTransport(handler)
        result = flare_tenant_exposure(since="2026-06-01", types=["stealer_log"])
        assert result["warnings"] == []
        return sleeps

    assert 10.0 in run(None)
    assert 4.0 in run("4")


def test_search_calls_are_spaced(monkeypatch):
    _use_http(monkeypatch)
    _clock()
    times: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/tokens/generate":
            return httpx.Response(200, json={"token": TOKEN, "refresh_token_exp": 1})
        times.append(flare_client.CLOCK())
        return httpx.Response(200, json={"items": [], "next": None})

    flare_client.TRANSPORT = httpx.MockTransport(handler)
    fetch_tenant_events({"filters": {"type": ["leak"]}}, limit=10)
    fetch_tenant_events({"filters": {"type": ["listing"]}}, limit=10)
    assert len(times) == 2
    assert times[1] - times[0] >= 1


def test_redirect_is_refused(monkeypatch):
    _use_http(monkeypatch)
    _clock()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/tokens/generate":
            return httpx.Response(200, json={"token": TOKEN, "refresh_token_exp": 1})
        return httpx.Response(302, headers={"location": "https://evil.example/steal"})

    flare_client.TRANSPORT = httpx.MockTransport(handler)
    result = flare_tenant_exposure(since="2026-06-01")
    assert result["data"] == []
    assert "evil.example" in result["warnings"][0]
    assert KEY not in result["warnings"][0]


def test_timeout_falls_back_to_cache(monkeypatch):
    _use_http(monkeypatch)
    state, _sleeps = _clock()
    calls = {"n": 0}
    payload = (FIXTURES / "tenant_events_synthetic.json").read_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/tokens/generate":
            return httpx.Response(200, json={"token": TOKEN, "refresh_token_exp": 1})
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, content=payload)
        raise httpx.TimeoutException("timed out")

    flare_client.TRANSPORT = httpx.MockTransport(handler)
    first = flare_tenant_exposure(since="2026-06-01", types=["stealer_log"])
    assert first["data"]
    state["t"] += 301
    second = flare_tenant_exposure(since="2026-06-01", types=["stealer_log"])
    assert second["cache"] == "stale"
    assert second["data"][0]["event_type"] == "stealer_log"
    assert calls["n"] == 2


def test_offline_without_cache_is_unavailable(monkeypatch):
    _use_http(monkeypatch)
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    result = flare_tenant_exposure(since="2026-06-01")
    assert result["data"] == []
    assert result["warnings"] == ["unavailable"]


def test_forbidden_names_the_env_var(monkeypatch):
    _use_http(monkeypatch)
    _clock()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/tokens/generate":
            return httpx.Response(403, json={"error": {"code": "FORBIDDEN", "message": "no"}})
        raise AssertionError("search must not run after a rejected token")

    flare_client.TRANSPORT = httpx.MockTransport(handler)
    result = flare_tenant_exposure(since="2026-06-01")
    assert "403" in result["warnings"][0]
    assert "FLARE_API_KEY" in result["warnings"][0]
    assert KEY not in result["warnings"][0]


def test_quota_header_is_recorded_and_floor_blocks(monkeypatch, tmp_path):
    _use_http(monkeypatch)
    _clock()
    payload = json.loads(
        (FIXTURES / "credentials_global_search_synthetic.json").read_text(encoding="utf-8")
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/tokens/generate":
            return httpx.Response(200, json={"token": TOKEN, "refresh_token_exp": 1})
        return httpx.Response(
            200,
            json=payload,
            headers={"X-Flare-Global-Searches-Remaining": "42"},
        )

    flare_client.TRANSPORT = httpx.MockTransport(handler)
    counted = flare_domain_credentials("example.com.au", since="2026-06-01")
    assert counted["data"][0]["count"] == 2
    assert quota_view()["remaining"] == 42
    status = flare_quota_status()
    assert status["data"]["remaining"] == 42
    flare_client.reset_token()
    record_global_search(3)
    (tmp_path / "config.yaml").write_text(
        "cyber_au:\n  premium:\n    flare:\n      global_search_floor: 10\n",
        encoding="utf-8",
    )
    called = {"n": 0}

    def blocked(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(500, json={})

    flare_client.TRANSPORT = httpx.MockTransport(blocked)
    refused = flare_domain_credentials("example.com.au")
    assert called["n"] == 0
    assert "floor" in refused["warnings"][0]
    assert KEY not in refused["warnings"][0]


def test_global_search_asks_above_daily_count_and_blocks_under_floor(monkeypatch, tmp_path):
    record_global_search(100)
    record_global_search(99)
    config = {
        "cyber_au": {
            "premium": {"flare": {"global_searches_per_day": 2, "global_search_floor": 1}}
        },
    }
    asked = global_search_decision(config, approved=False)
    assert asked["decision"] == "ask"
    assert asked["needs_approval"] is True
    assert KEY not in asked["message"]
    allowed = global_search_decision(config, approved=True)
    assert allowed is None
    record_global_search(0)
    blocked = global_search_decision(config, approved=True)
    assert blocked["block"] is True
    assert "floor" in blocked["message"]
    record_global_search(50)
    (tmp_path / "config.yaml").write_text(
        "cyber_au:\n"
        "  premium:\n"
        "    flare:\n"
        "      global_searches_per_day: 1\n"
        "      global_search_floor: 1\n",
        encoding="utf-8",
    )
    _use_fixtures(monkeypatch)
    _watchlist(tmp_path)
    refused = flare_domain_credentials("example.com.au")
    assert refused["data"] == []
    assert "Approval required" in refused["warnings"][0]
    assert KEY not in refused["warnings"][0]
    record_global_search(0)
    tenant = flare_tenant_exposure(since="2026-06-01")
    assert any(row["event_type"] == "stealer_log" for row in tenant["data"])
    assert all("floor" not in warning for warning in tenant["warnings"])


def test_highlight_password_is_redacted(monkeypatch, tmp_path):
    _watchlist(tmp_path)
    payload = json.loads((FIXTURES / "tenant_events_synthetic.json").read_text(encoding="utf-8"))
    payload["items"] = [payload["items"][0]]
    payload["items"][0]["highlights"] = {"title": ["password=hunter2"]}
    _use_fixtures(monkeypatch, _copy(tmp_path, payload))
    result = flare_tenant_exposure(since="2026-06-01", types=["stealer_log"])
    blob = json.dumps(result)
    assert "hunter2" not in blob
    assert "<<untrusted source=flare>>" in blob
    assert (
        not (tmp_path / "intel.sqlite").exists()
        or b"hunter2" not in (tmp_path / "intel.sqlite").read_bytes()
    )
