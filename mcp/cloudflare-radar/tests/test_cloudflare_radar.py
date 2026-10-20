"""Cloudflare Radar connector tests. Every response is a synthetic fixture."""

import asyncio
import json
import time
from pathlib import Path

import cyberau_cloudflare_radar.source as source
import httpx
import jsonschema
import pytest
from cyberau_cloudflare_radar.source import (
    TOKEN_ENV,
    connector,
    get_radar_annotations_outages,
    get_radar_attacks_layer7_summary,
    get_radar_bgp_hijacks_events,
    get_radar_bgp_leaks_events,
    get_radar_ranking_domain,
    get_radar_ranking_top,
)
from cyberau_common.server import build_server

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ROOT = Path(__file__).resolve().parents[1]
TOKEN = "test-only-radar-token-not-a-secret"
_DEFAULT_RETRIES = source._RETRIES


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    source._SLEEP = lambda _seconds: None
    source._LIMIT_SLEEP = lambda _seconds: None
    yield
    source._TRANSPORT = None
    source._SLEEP = time.sleep
    source._LIMIT_SLEEP = time.sleep
    source._CLOCK = time.monotonic
    source._RETRIES = _DEFAULT_RETRIES


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _serve(routes: dict[str, str], seen: list | None = None, status: int = 200, headers=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        path = request.url.path.removeprefix("/client/v4/radar")
        name = routes.get(path)
        if name is None:
            return httpx.Response(404, json={"success": False, "errors": [], "result": None})
        return httpx.Response(status, json=_fixture(name), headers=headers or {})

    source._TRANSPORT = httpx.MockTransport(handler)


def _valid(tool: str, payload: dict) -> None:
    schema = json.loads((ROOT / "schema" / f"{tool}.response.json").read_text("utf-8"))
    jsonschema.validate(payload["data"], schema)
    assert payload["untrusted"] is True
    assert payload["attribution"].startswith("Source: Cloudflare Radar (CC BY-NC 4.0)")


def test_tools_are_read_only_and_names_fit():
    listed = asyncio.run(build_server(connector()).list_tools())
    names = sorted(tool.name for tool in listed)
    assert names == sorted(fn.__name__ for fn, _text in source.TOOLS)
    for tool in listed:
        assert tool.annotations.readOnlyHint is True
        assert tool.annotations.destructiveHint is False
        assert len(f"mcp__cloudflare_radar__{tool.name}") <= 64
        schema = json.loads((ROOT / "schema" / f"{tool.name}.input.json").read_text("utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)


def test_outages_send_the_token_and_wrap_free_text(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    seen: list[httpx.Request] = []
    _serve({"/annotations/outages": "get_radar_annotations_outages_AU.json"}, seen)
    result = get_radar_annotations_outages(location="au", date_range="28d", limit=5)
    _valid("get_radar_annotations_outages", result)
    assert seen[0].headers["authorization"] == f"Bearer {TOKEN}"
    assert seen[0].url.params["location"] == "AU"
    assert seen[0].url.params["dateRange"] == "28d"
    assert seen[0].url.params["limit"] == "5"
    row = result["data"]["outages"][0]
    assert row["locations"] == ["AU"]
    assert row["cause"] == "POWER_OUTAGE"
    assert row["description"].startswith("<<untrusted source=cloudflare-radar>>")
    assert row["scope"].startswith("<<untrusted source=cloudflare-radar>>")
    assert row["linked_url"] is None
    assert TOKEN not in json.dumps(result)


def test_empty_outages_say_so(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    _serve({"/annotations/outages": "get_radar_annotations_outages_empty.json"})
    result = get_radar_annotations_outages(location="AU")
    assert result["data"]["outages"] == []
    assert "no outages in this window" in result["warnings"]


def test_layer7_summary_keeps_numbers_and_codes(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    seen: list[httpx.Request] = []
    _serve(
        {"/attacks/layer7/summary/mitigation_product": "get_radar_attacks_layer7_summary_AU.json"},
        seen,
    )
    result = get_radar_attacks_layer7_summary(location="AU")
    _valid("get_radar_attacks_layer7_summary", result)
    shares = result["data"]["share_percent"]
    assert shares == {"WAF": 61.5, "DDOS": 30.25}
    assert result["data_as_of"] == "2026-10-20"
    assert get_radar_attacks_layer7_summary(dimension="nope")["data"] is None


def test_bgp_events_keep_only_listed_fields(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    seen: list[httpx.Request] = []
    _serve(
        {
            "/bgp/hijacks/events": "get_radar_bgp_hijacks_events.json",
            "/bgp/leaks/events": "get_radar_bgp_leaks_events.json",
        },
        seen,
    )
    hijacks = get_radar_bgp_hijacks_events(involved_asn=64502, limit=3)
    _valid("get_radar_bgp_hijacks_events", hijacks)
    event = hijacks["data"]["events"][0]
    assert "secret_field" not in event
    assert event["prefixes"] == ["192.0.2.0/24"]
    assert hijacks["data"]["asn_info"][0]["org_name"].startswith("<<untrusted")
    assert seen[0].url.params["involvedAsn"] == "64502"
    assert seen[0].url.params["per_page"] == "3"

    leaks = get_radar_bgp_leaks_events(involved_country="nz")
    _valid("get_radar_bgp_leaks_events", leaks)
    assert leaks["data"]["events"][0]["countries"] == ["NZ", "AU"]
    assert seen[1].url.params["involvedCountry"] == "NZ"


def test_ranking_top_and_domain(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    _serve(
        {
            "/ranking/top": "get_radar_ranking_top.json",
            "/ranking/domain/example.com": "get_radar_ranking_domain_ranked.json",
            "/ranking/domain/unknown.example": "get_radar_ranking_domain_unranked.json",
        }
    )
    top = get_radar_ranking_top(location="AU", limit=2)
    _valid("get_radar_ranking_top", top)
    assert [row["domain"] for row in top["data"]["domains"]] == ["example.com", "example.net"]
    assert top["data_as_of"] == "2026-10-20"

    ranked = get_radar_ranking_domain("Example.COM.")
    _valid("get_radar_ranking_domain", ranked)
    assert ranked["data"]["rank"] == 1200
    assert ranked["data"]["categories"][0].startswith("<<untrusted")

    unranked = get_radar_ranking_domain("unknown.example")
    _valid("get_radar_ranking_domain", unranked)
    assert unranked["data"]["rank"] is None
    assert "domain is not in the Radar top ranking" in unranked["warnings"]


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (lambda: get_radar_annotations_outages(location="Australia"), "two-letter"),
        (lambda: get_radar_annotations_outages(date_range="3d"), "date_range"),
        (lambda: get_radar_annotations_outages(limit=0), "limit"),
        (lambda: get_radar_bgp_hijacks_events(involved_asn=-1), "asn"),
        (lambda: get_radar_ranking_domain("not a domain"), "hostname"),
    ],
)
def test_bad_arguments_never_reach_the_network(call, message, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    seen: list[httpx.Request] = []
    _serve({}, seen)
    result = call()
    assert result["data"] is None
    assert any(message in warning for warning in result["warnings"])
    assert seen == []


def test_missing_token_names_the_variable_and_makes_no_call():
    seen: list[httpx.Request] = []
    _serve({"/ranking/top": "get_radar_ranking_top.json"}, seen)
    result = get_radar_ranking_top()
    assert result["data"] is None
    assert any(TOKEN_ENV in warning for warning in result["warnings"])
    assert seen == []


@pytest.mark.parametrize("status", [401, 403])
def test_refused_token_is_explained_without_echoing_it(status, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    _serve({"/ranking/top": "radar_401.json"}, status=status)
    result = get_radar_ranking_top()
    assert result["data"] is None
    assert any("Radar > Read" in warning for warning in result["warnings"])
    assert TOKEN not in json.dumps(result)


def test_rate_limit_reports_retry_after(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    source._RETRIES = 0
    _serve({"/ranking/top": "radar_429.json"}, status=429, headers={"retry-after": "300"})
    result = get_radar_ranking_top()
    assert result["data"] is None
    assert any("Retry after 300 seconds" in warning for warning in result["warnings"])


def test_cache_serves_offline_and_stale_on_failure(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    _serve({"/ranking/top": "get_radar_ranking_top.json"})
    first = get_radar_ranking_top()
    assert first["cache"] == "miss"

    def down(_request):
        raise httpx.ConnectError("down")

    source._TRANSPORT = httpx.MockTransport(down)
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    offline = get_radar_ranking_top()
    assert offline["cache"] in {"hit", "stale"}
    assert offline["data"]["domains"]

    monkeypatch.delenv("CYBERAU_OFFLINE")
    nothing = get_radar_ranking_top(location="NZ")
    assert nothing["data"] is None
    assert nothing["warnings"]


def test_health(monkeypatch):
    probe = connector().health(live=False)
    assert probe.ok is True
    unset = connector().health(live=True, check_schema=True)
    assert unset.ok is False
    assert TOKEN_ENV in unset.detail

    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    _serve(
        {
            "/annotations/outages": "get_radar_annotations_outages_AU.json",
            "/ranking/top": "get_radar_ranking_top.json",
        }
    )
    live = connector().health(live=True, check_schema=True)
    assert live.ok is True, live.detail

    _serve({"/annotations/outages": "radar_401.json"}, status=401)
    refused = connector().health(live=True, check_schema=True)
    assert refused.ok is False
    assert TOKEN not in refused.detail
