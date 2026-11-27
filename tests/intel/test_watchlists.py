"""Watchlist matching, nightly recompute and the crt.sh lookalike path."""

from __future__ import annotations

import ipaddress
import json
import sys
import time
from pathlib import Path

import httpx
import pytest
from cyberau_common import egress
from store.api import upsert_advisory, upsert_indicator
from store.canonical import utc_now
from store.cli import main
from store.db import open_store
from store.watchlists import (
    TEMPLATE_PATH,
    Watchlist,
    hits,
    list_matches,
    load_watchlist,
    lookalike,
    match_indicator,
    match_text,
    run_watchlist,
)

SEEN = "2026-10-17T00:00:00Z"
WATCHLIST = """\
domains:
  - example.com
brands:
  - Example Brand
ip_ranges:
  - 192.0.2.0/24
  - 2001:db8::/32
asns:
  - AS64496
vendors:
  - Fortinet
  - name: Example Vendor
    aliases: [ExampleOS]
"""


def _watch(text: str = WATCHLIST, tmp_path: Path | None = None) -> Watchlist:
    path = (tmp_path or Path(".")) / "w.yaml"
    path.write_text(text, encoding="utf-8")
    return load_watchlist(path)


def _indicator(kind: str, value: str, raw: bytes | None = None) -> str:
    return upsert_indicator(
        kind, value, source="fixture", observed_at=SEEN, raw=raw or value.encode()
    )


def _advisory(ident: str, title: str, summary: str | None = None) -> None:
    upsert_advisory(
        ident,
        source="fixture",
        title=title,
        url=f"https://advisories.example.org/{ident}",
        published_at=SEEN,
        summary=summary,
        content_sha256=None,
    )


def _write(store_path: Path, text: str = WATCHLIST) -> Path:
    path = store_path.parent / "watchlists.yaml"
    path.write_text(text, encoding="utf-8")
    return path


# Parsing and pure matching.


def test_parse_keeps_good_entries_and_warns_without_echoing(tmp_path):
    watch = _watch(
        "domains: [Example.COM., 'not a host', '*.example.net']\n"
        "ip_ranges: [192.0.2.0/24, nonsense]\n"
        "asns: [AS64496, 64497, as64498, -1, ASx]\n"
        "vendors: [microsoft, {name: Example Vendor, aliases: [ExampleOS]}]\n",
        tmp_path,
    )
    assert watch.domains == ("example.com", "example.net")
    assert [str(net) for net in watch.ip_ranges] == ["192.0.2.0/24"]
    assert watch.asns == (64496, 64497, 64498)
    microsoft = next(vendor for vendor in watch.vendors if vendor.name == "Microsoft")
    assert "MSFT" in microsoft.aliases
    assert len(watch.warnings) == 4
    assert all("nonsense" not in item and "not a host" not in item for item in watch.warnings)


def test_cidr_containment_ipv4_ipv6_and_url_host(tmp_path):
    watch = _watch(tmp_path=tmp_path)
    inside = match_indicator(watch, "i1", "ipv4", "192.0.2.10")
    assert [(m.kind, m.value) for m in inside] == [("ip_range", "192.0.2.0/24")]
    assert match_indicator(watch, "i2", "ipv4", "192.0.3.10") == []
    v6 = match_indicator(watch, "i3", "ipv6", "2001:db8::1")
    assert [m.value for m in v6] == ["2001:db8::/32"]
    assert match_indicator(watch, "i4", "ipv6", "2001:db9::1") == []
    narrower = match_indicator(watch, "i5", "cidr", "192.0.2.128/25")
    assert narrower[0].detail == "cidr inside 192.0.2.0/24"
    wider = match_indicator(watch, "i6", "cidr", "192.0.0.0/16")
    assert wider[0].detail == "cidr covers 192.0.2.0/24"
    assert match_indicator(watch, "i7", "cidr", "198.51.100.0/24") == []
    url = match_indicator(watch, "i8", "url", "http://192.0.2.5/login")
    assert [m.kind for m in url] == ["ip_range"]


def test_asn_equality(tmp_path):
    watch = _watch(tmp_path=tmp_path)
    assert [m.value for m in match_indicator(watch, "a", "asn", "AS64496")] == ["AS64496"]
    assert match_indicator(watch, "b", "asn", "AS64497") == []


def test_exact_and_subdomain(tmp_path):
    watch = _watch(tmp_path=tmp_path)
    exact = match_indicator(watch, "d1", "domain", "example.com")
    assert [(m.kind, m.detail) for m in exact] == [("domain", "domain equal")]
    sub = match_indicator(watch, "d2", "url", "https://login.example.com/x")
    assert [(m.kind, m.detail) for m in sub] == [("domain", "url subdomain")]
    mail = match_indicator(watch, "d3", "email", "someone@mail.example.com")
    assert [m.kind for m in mail] == ["domain"]
    assert match_indicator(watch, "d4", "domain", "notexample.org") == []


@pytest.mark.parametrize(
    ("host", "rule"),
    [
        ("examp1e.com", "homoglyph"),
        ("exarnple.com", "homoglyph"),
        ("xn--xampl-ywef.com", "homoglyph"),  # Cyrillic e in both places
        ("example.net", "suffix-swap"),
        ("example-login.com", "token"),
        ("exampel.com", None),  # transposition is two edits, above the limit for 7 letters
        ("exmple.com", "edit-distance-1"),
        ("cdn.examp1e.com", "homoglyph"),
        ("example.com", None),
        ("www.example.com", None),
        ("unrelated.org", None),
    ],
)
def test_lookalike_rules(host, rule):
    assert lookalike(host, "example.com") == rule


def test_lookalike_indicator_is_recorded(tmp_path):
    watch = _watch(tmp_path=tmp_path)
    found = match_indicator(watch, "d5", "domain", "examp1e.com")
    assert [(m.kind, m.detail) for m in found] == [("lookalike", "domain homoglyph")]


def test_vendor_aliases_and_brand_tokens(tmp_path):
    watch = _watch(tmp_path=tmp_path)
    forti = match_text(watch, "adv1", "FortiOS SSL VPN flaw", "FortiOS SSL VPN flaw")
    assert [(m.kind, m.value, m.detail) for m in forti] == [("vendor", "Fortinet", "alias FortiOS")]
    own = match_text(watch, "adv2", "t", "Patch for exampleos 3.1 released")
    assert [m.value for m in own] == ["Example Vendor"]
    brand = match_text(watch, "adv3", "t", "Scam texts impersonate EXAMPLE-brand Pty Ltd")
    assert [(m.kind, m.value) for m in brand] == [("brand", "Example Brand")]
    # Tokens must be consecutive: a split or squashed phrase does not match.
    assert match_text(watch, "adv4", "t", "Example products and a brand refresh") == []
    assert match_text(watch, "adv5", "t", "examplebrand portal") == []
    assert match_text(watch, "adv6", "t", "Fortification of systems") == []


# Store recompute.


def test_run_records_matches_and_routine_state(store_path):
    _write(store_path)
    _indicator("ipv4", "192.0.2.7")
    _indicator("domain", "examp1e.com")
    _indicator("asn", "AS64496")
    _indicator("domain", "unrelated.org")
    _advisory("fixture:1", "FortiGate flaw exploited", "Advice for Example Brand customers")
    summary = run_watchlist(store=store_path, now="2026-10-17T10:00:00Z")
    assert summary["status"] == "ok"
    assert summary["matches"] == 5
    assert summary["new"] == 5
    assert summary["by_kind"] == {
        "asn": 1,
        "brand": 1,
        "ip_range": 1,
        "lookalike": 1,
        "vendor": 1,
    }
    assert "example.com" not in json.dumps(summary)
    conn = open_store(store_path).connection()
    state = conn.execute(
        "SELECT watermark, updated_at FROM routine_state WHERE routine = 'watchlist'"
    ).fetchone()
    assert tuple(state) == ("2026-10-17T10:00:00Z", "2026-10-17T10:00:00Z")

    again = run_watchlist(store=store_path, now="2026-10-18T10:00:00Z")
    assert again["new"] == 0
    assert again["removed"] == 0
    rows = list_matches(store=store_path)
    assert {row["first_matched"] for row in rows} == {"2026-10-17T10:00:00Z"}
    assert {row["last_matched"] for row in rows} == {"2026-10-18T10:00:00Z"}
    assert list_matches(store=store_path, since="2026-10-18T00:00:00Z") == []
    assert [row["list"] for row in list_matches(store=store_path, lists=["asns"])] == ["asns"]


def test_recompute_drops_matches_for_removed_rows_and_entries(store_path):
    path = _write(store_path)
    indicator = _indicator("ipv4", "192.0.2.7")
    _indicator("asn", "AS64496")
    _advisory("fixture:1", "FortiGate flaw exploited")
    run_watchlist(store=store_path, now="2026-10-17T10:00:00Z")
    assert {row["ref_kind"] for row in list_matches(store=store_path)} == {
        "indicator",
        "advisory",
    }
    conn = open_store(store_path).connection()
    conn.execute("DELETE FROM indicators WHERE id = ?", (indicator,))
    conn.execute("DELETE FROM advisories WHERE id = 'fixture:1'")
    # The delete triggers drop the matches before the next run.
    assert [row["kind"] for row in list_matches(store=store_path)] == ["asn"]
    # A row removed behind the triggers' back is still dropped by the next run.
    conn.execute(
        "INSERT INTO watchlist_matches VALUES"
        " ('ip_ranges','ip_range','192.0.2.0/24','indicator','gone','192.0.2.9','',?,?)",
        ("2026-10-17T10:00:00Z", "2026-10-17T10:00:00Z"),
    )
    assert len(list_matches(store=store_path)) == 1
    summary = run_watchlist(store=store_path, now="2026-10-18T10:00:00Z")
    assert summary["removed"] == 1
    assert summary["matches"] == 1
    path.write_text("domains: [example.com]\n", encoding="utf-8")
    summary = run_watchlist(store=store_path, now="2026-10-19T10:00:00Z")
    assert summary["removed"] == 1
    assert list_matches(store=store_path) == []


def test_hits_use_the_briefing_shape(store_path):
    _write(store_path)
    _indicator("ipv4", "192.0.2.7")
    run_watchlist(store=store_path, now="2026-10-17T10:00:00Z")
    payload = hits(store=store_path, since="2026-10-17T00:00:00Z")
    assert payload["untrusted"] is True
    [row] = payload["data"]["hits"]
    assert set(row) == {"id", "kind", "value", "seen", "asset"}
    assert row["kind"] == "ip_range"
    assert row["value"] == "192.0.2.7"
    assert row["seen"] == "2026-10-17T10:00:00Z"
    assert row["asset"] == "192.0.2.0/24"
    assert hits(store=store_path, since="2026-10-18")["data"]["hits"] == []


# CLI.


def _cli(argv: list[str], capsys) -> tuple[int, dict]:
    code = main(argv)
    out = capsys.readouterr().out
    return code, json.loads(out) if out.strip() else {}


def test_missing_watchlist_is_a_clean_no_op(store_path, capsys):
    code, payload = _cli(["watchlist", "run"], capsys)
    assert code == 0
    assert payload["status"] == "skipped"
    assert payload["detail"] == "no watchlist configured"
    assert not store_path.exists()


def test_removing_the_file_clears_old_matches(store_path, capsys):
    path = _write(store_path)
    _indicator("asn", "AS64496")
    assert _cli(["watchlist", "run"], capsys)[1]["matches"] == 1
    path.unlink()
    code, payload = _cli(["watchlist", "run"], capsys)
    assert (code, payload["status"], payload["removed"]) == (0, "skipped", 1)
    assert list_matches(store=store_path) == []


def test_bad_yaml_fails_with_exit_one(store_path, capsys):
    _write(store_path, "domains: [unclosed\n")
    code, payload = _cli(["watchlist", "run"], capsys)
    assert code == 1
    assert payload["status"] == "error"


def test_init_writes_template_and_never_overwrites(store_path, capsys):
    target = store_path.parent / "watchlists.yaml"
    code, payload = _cli(["watchlist", "init"], capsys)
    assert (code, payload["created"]) == (0, True)
    assert target.read_text(encoding="utf-8") == TEMPLATE_PATH.read_text(encoding="utf-8")
    target.write_text("domains: [example.org]\n", encoding="utf-8")
    code, payload = _cli(["watchlist", "init"], capsys)
    assert (code, payload["created"]) == (0, False)
    assert target.read_text(encoding="utf-8") == "domains: [example.org]\n"


def test_cli_matches_and_hits(store_path, capsys):
    _write(store_path)
    _indicator("domain", "examp1e.com")
    assert _cli(["watchlist", "run"], capsys)[0] == 0
    code, payload = _cli(["watchlist", "matches", "--list", "domains"], capsys)
    assert code == 0
    assert [row["kind"] for row in payload["matches"]] == ["lookalike"]
    code, payload = _cli(["watchlist", "hits", "--since", "2026-01-01"], capsys)
    assert code == 0
    assert payload["data"]["hits"][0]["value"] == "examp1e.com"


def test_template_matches_nothing_and_is_read_by_org_exposure(tmp_path):
    watch = load_watchlist(TEMPLATE_PATH)
    assert watch.warnings == ()
    assert watch.domains == ("example.com", "example.com.au")
    assert watch.asns == (64496,)
    from cyberau_org_exposure.watchlist import _routine_lists

    domains, brands, warnings = _routine_lists(TEMPLATE_PATH)
    assert domains == ["example.com", "example.com.au"]
    assert brands == ["Example Brand"]
    assert warnings == []


# crt.sh lookalike discovery.

_CERTS = [
    {
        "issuer_name": "C=US, O=Example CA",
        "common_name": "example.com",
        "name_value": "example.com\nwww.example.com\nexamp1e.com\n*.exarnple.com\nunrelated.org",
        "id": 101,
        "entry_timestamp": "2026-10-10T00:00:00",
        "not_before": "2026-10-01T00:00:00",
        "not_after": "2027-10-01T00:00:00",
        "serial_number": "0abc01",
    }
]


@pytest.fixture
def crtsh(monkeypatch):
    from cyberau_crtsh import source

    for name in (
        "CYBERAU_OFFLINE",
        "CYBERAU_CRTSH_SNAPSHOT",
        "CYBERAU_AUDIT_LOG_PATH",
        "CYBERAU_EGRESS_ALLOWLIST",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CYBERAU_TODAY", "2026-10-17")
    requests: list[httpx.Request] = []
    state = {"t": 0.0, "resolved": []}

    def resolve(host: str):
        # DNS belongs to the direct socket transport. MockTransport must not
        # resolve anything; record an unexpected lookup without using DNS.
        state["resolved"].append(host)
        return [ipaddress.ip_address("1.2.3.4")]

    monkeypatch.setattr(egress, "_resolve", resolve)

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=_CERTS)

    def sleeper(seconds: float) -> None:
        state["t"] += float(seconds)

    source._TRANSPORT = httpx.MockTransport(handler)
    source._SLEEP = sleeper
    source._CLOCK = lambda: state["t"]
    yield requests, state
    source._TRANSPORT = None
    source._SLEEP = time.sleep
    source._CLOCK = time.monotonic


def _audit_records(store_path: Path) -> list[dict]:
    lines = []
    for path in sorted((store_path.parent / "audit").glob("*.jsonl")):
        lines.extend(json.loads(line) for line in path.read_text().splitlines() if line)
    return lines


def test_crtsh_lookalikes_only_contact_crtsh_and_are_audited(store_path, crtsh):
    requests, state = crtsh
    _write(store_path)
    _indicator("asn", "AS64496")
    summary = run_watchlist(store=store_path, crtsh=True, now="2026-10-17T10:00:00Z")
    assert summary["crtsh"]["queried"] == 1
    assert summary["crtsh"]["matches"] == 2
    found = {
        row["ref"]: row["detail"]
        for row in list_matches(store=store_path)
        if row["ref_kind"] == "crtsh"
    }
    assert found == {"examp1e.com": "crt.sh homoglyph", "exarnple.com": "crt.sh homoglyph"}

    assert requests, "crt.sh was not queried"
    assert {request.url.host for request in requests} == {"crt.sh"}
    assert state["resolved"] == []
    assert [request.url.params["q"] for request in requests] == ["%.example.com"]
    others = ("Example Brand", "Example Vendor", "192.0.2", "2001:db8", "64496", "Fortinet")
    for request in requests:
        sent = str(request.url) + request.content.decode() + json.dumps(dict(request.headers))
        assert not any(value.lower() in sent.lower() for value in others)

    records = [
        record
        for record in _audit_records(store_path)
        if record.get("tool") == "crtsh_certs" and record["event"] == "tool_call"
    ]
    assert len(records) == 1
    assert records[0]["args_redacted"] == {"domain": "example.com", "include_subdomains": True}
    assert "watchlist" in records[0]["flags"]


def test_crtsh_is_not_called_without_the_flag(store_path, crtsh):
    requests, _state = crtsh
    _write(store_path)
    summary = run_watchlist(store=store_path, now="2026-10-17T10:00:00Z")
    assert summary["crtsh"] == {"enabled": False}
    assert requests == []
    assert _audit_records(store_path) == []


def test_crtsh_failure_warns_keeps_recent_matches_then_ages_them_out(
    store_path, crtsh, monkeypatch
):
    _write(store_path)
    run_watchlist(store=store_path, crtsh=True, now="2026-10-17T10:00:00Z")
    assert len(list_matches(store=store_path)) == 2
    # A repeat within 24 hours is served from the connector cache, so fail the call itself.
    source = sys.modules["cyberau_crtsh.source"]
    failed = {"data": [], "warnings": ["upstream status 503"], "cache": "snapshot"}
    monkeypatch.setattr(source, "crtsh_certs", lambda *args, **kwargs: failed)
    summary = run_watchlist(store=store_path, crtsh=True, now="2026-10-18T10:00:00Z")
    assert summary["status"] == "ok"
    assert summary["crtsh"]["failed"] == 1
    assert any("crt.sh query failed" in item for item in summary["warnings"])
    assert len(list_matches(store=store_path)) == 2
    summary = run_watchlist(store=store_path, now="2026-10-30T10:00:00Z")
    assert summary["removed"] == 2
    assert list_matches(store=store_path) == []


def test_crtsh_missing_connector_is_a_warning(store_path, monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "cyberau_crtsh", None)
    monkeypatch.setitem(sys.modules, "cyberau_crtsh.source", None)
    _write(store_path)
    code, payload = _cli(["watchlist", "run", "--crtsh"], capsys)
    assert code == 0
    assert payload["crtsh"]["skipped"] == "crt.sh connector is not installed"
    assert payload["status"] == "ok"


# Watches over feed items and advisories.

WATCHES = """\
feeds:
  - id: azure-updates
    url: https://updates.example/rss
watches:
  - name: ms-changes
    title: Microsoft security changes
    sources: [azure-updates]
    any: [Defender, Sentinel]
    exclude: [webinar]
    lookback_days: 2
  - name: entra-ca
    title: Entra Conditional Access
    all: [Entra, Conditional Access]
"""


def _feed_item(ident: str, title: str, published: str, source: str = "feed-azure-updates"):
    upsert_advisory(
        f"{source}:{ident}",
        source=source,
        title=title,
        url=f"https://updates.example/{ident}",
        published_at=published,
        summary=None,
        content_sha256=None,
    )


def test_watches_match_sources_terms_and_window(store_path):
    _write(store_path, WATCHES)
    _feed_item("a", "Defender for Cloud adds agentless scanning", "2026-10-19T08:00:00Z")
    _feed_item("b", "Sentinel webinar next week", "2026-10-19T08:00:00Z")
    _feed_item("c", "Defender retired feature", "2026-10-10T08:00:00Z")
    _feed_item("d", "Defender in another feed", "2026-10-19T08:00:00Z", source="feed-other")
    _feed_item("e", "Larger VM sizes", "2026-10-19T08:00:00Z")
    _feed_item("f", "Entra Conditional Access session controls", "2026-10-19T08:00:00Z", "auscert")
    summary = run_watchlist(store=store_path, now="2026-10-20T04:00:00Z")
    assert summary["entries"]["watches"] == 2
    assert summary["by_kind"] == {"watch": 2}
    rows = list_matches(store=store_path, lists=["watches"])
    assert {(row["value"], row["ref"]) for row in rows} == {
        ("Microsoft security changes", "feed-azure-updates:a"),
        ("Entra Conditional Access", "auscert:f"),
    }
    payload = hits(store=store_path, since="2026-10-20T00:00:00Z")
    by_ref = {row["value"]: row for row in payload["data"]["hits"]}
    row = by_ref["Defender for Cloud adds agentless scanning"]
    assert row["watch"] == "Microsoft security changes"
    assert row["url"] == "https://updates.example/a"
    assert row["source"] == "feed-azure-updates"
    assert row["published"] == "2026-10-19T08:00:00Z"
    assert "asset" not in row


def test_watch_window_follows_the_run_not_the_clock(store_path):
    _write(store_path, WATCHES)
    _feed_item("old", "Defender adds agentless scanning", "2001-01-09T00:00:00Z")
    _feed_item("today", "Sentinel adds a connector", utc_now())
    # A window anchored on the wall clock would keep only the item published today.
    summary = run_watchlist(store=store_path, now="2001-01-10T00:00:00Z")
    assert summary["by_kind"] == {"watch": 2}
    summary = run_watchlist(store=store_path, now="2099-01-10T00:00:00Z")
    assert summary["matches"] == 0


def test_watch_window_reads_an_offset_now_as_utc(store_path):
    _write(store_path, WATCHES)
    _feed_item("edge", "Defender adds agentless scanning", "2001-01-08T00:30:00Z")
    # 10:00+10:00 is 00:00Z, so the 2-day window opens at 2001-01-08T00:00:00Z.
    summary = run_watchlist(store=store_path, now="2001-01-10T10:00:00+10:00")
    assert summary["by_kind"] == {"watch": 1}
    assert list_matches(store=store_path)[0]["last_matched"] == "2001-01-10T00:00:00Z"


def test_packs_without_the_connector_warn(store_path, monkeypatch):
    import builtins

    real = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name.startswith("cyberau_custom_feeds"):
            raise ImportError(name)
        return real(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    _write(store_path, "packs: [microsoft-security]\n")
    summary = run_watchlist(store=store_path, now="2026-10-20T04:00:00Z")
    assert any("custom-feeds connector" in item for item in summary["warnings"])


# Cloudflare Radar BGP events for watched ASNs.

RADAR_TOKEN = "test-only-radar-token-not-a-secret"
_HIJACKS = {
    "success": True,
    "errors": [],
    "result": {
        "asn_info": [{"asn": 64511, "org_name": "Synthetic Hijacker", "country_code": "AU"}],
        "events": [
            {
                "id": 7001,
                "hijacker_asn": 64511,
                "hijacker_country": "AU",
                "victim_asns": [64496],
                "victim_countries": ["AU"],
                "prefixes": ["192.0.2.0/24"],
                "min_hijack_ts": "2026-10-16T01:00:00",
                "max_hijack_ts": "2026-10-16T01:05:00",
                "duration": 300,
                "confidence_score": 9,
                "is_stale": False,
            },
            {
                "id": 7002,
                "hijacker_asn": 64500,
                "victim_asns": [64501],
                "prefixes": ["198.51.100.0/24"],
            },
        ],
    },
}
_LEAKS = {
    "success": True,
    "errors": [],
    "result": {
        "asn_info": [],
        "events": [
            {
                "id": 8001,
                "leak_asn": 64496,
                "leak_seg": [64510, 64496, 64512],
                "leak_type": 1,
                "countries": ["AU"],
                "detected_ts": "2026-10-16T02:00:00",
                "prefix_count": 4,
            }
        ],
    },
}
RADAR_CONFIG = "mcp_servers:\n  crtsh:\n    enabled: true\n  cloudflare_radar:\n    enabled: true\n"


@pytest.fixture
def radar(monkeypatch):
    from cyberau_cloudflare_radar import source

    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.delenv("CYBERAU_AUDIT_LOG_PATH", raising=False)
    monkeypatch.delenv("CYBERAU_EGRESS_ALLOWLIST", raising=False)
    monkeypatch.setenv(source.TOKEN_ENV, RADAR_TOKEN)
    requests: list[httpx.Request] = []
    state = {"status": 200}

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if state["status"] != 200:
            return httpx.Response(state["status"], json={"success": False})
        body = _HIJACKS if request.url.path.endswith("/bgp/hijacks/events") else _LEAKS
        return httpx.Response(200, json=body)

    monkeypatch.setattr(egress, "_resolve", lambda host: [ipaddress.ip_address("1.2.3.4")])
    source._TRANSPORT = httpx.MockTransport(handler)
    source._SLEEP = lambda _seconds: None
    source._LIMIT_SLEEP = lambda _seconds: None
    yield requests, state
    source._TRANSPORT = None
    source._SLEEP = time.sleep
    source._LIMIT_SLEEP = time.sleep


def test_radar_bgp_events_for_watched_asns_are_matched_and_audited(store_path, radar):
    requests, _state = radar
    _write(store_path)
    summary = run_watchlist(store=store_path, radar=True, now="2026-10-17T10:00:00Z")
    assert summary["radar"] == {"enabled": True, "queried": 2, "failed": 0, "matches": 2}
    found = {
        row["ref"]: (row["kind"], row["value"], row["detail"])
        for row in list_matches(store=store_path)
        if row["ref_kind"] == "radar"
    }
    assert found == {
        "hijack:7001": (
            "bgp_hijack",
            "AS64496",
            "Radar BGP hijack, watched ASN is the victim, confidence 9,"
            " started 2026-10-16T01:00:00",
        ),
        "leak:8001": (
            "bgp_leak",
            "AS64496",
            "Radar route leak, watched ASN is the leaker, detected 2026-10-16T02:00:00",
        ),
    }
    assert {request.url.host for request in requests} == {"api.cloudflare.com"}
    assert sorted(request.url.params["involvedAsn"] for request in requests) == ["64496"] * 2
    records = [
        record
        for record in _audit_records(store_path)
        if record["event"] == "tool_call" and "radar" in record.get("flags", [])
    ]
    assert sorted(record["tool"] for record in records) == [
        "get_radar_bgp_hijacks_events",
        "get_radar_bgp_leaks_events",
    ]
    assert all(record["args_redacted"]["involved_asn"] == 64496 for record in records)
    assert all(RADAR_TOKEN not in json.dumps(record) for record in _audit_records(store_path))

    payload = hits(store=store_path, since="2026-10-17T00:00:00Z")["data"]["hits"]
    kinds = sorted(hit["kind"] for hit in payload if hit.get("asset") == "AS64496")
    assert kinds == ["bgp_hijack", "bgp_leak"]


def test_radar_without_a_token_or_asns_is_skipped(store_path, radar, monkeypatch):
    requests, _state = radar
    _write(store_path, "domains: [example.com]\n")
    summary = run_watchlist(store=store_path, radar=True, now="2026-10-17T10:00:00Z")
    assert summary["radar"]["skipped"] == "no watched ASNs"
    _write(store_path)
    monkeypatch.delenv("CLOUDFLARE_RADAR_API_TOKEN")
    summary = run_watchlist(store=store_path, radar=True, now="2026-10-17T10:00:00Z")
    assert summary["status"] == "ok"
    assert "CLOUDFLARE_RADAR_API_TOKEN is not set" in summary["radar"]["skipped"]
    assert requests == []
    assert _audit_records(store_path) == []


def test_radar_failure_keeps_recent_matches_then_ages_them_out(store_path, radar, monkeypatch):
    _write(store_path)
    run_watchlist(store=store_path, radar=True, now="2026-10-17T10:00:00Z")
    assert len(list_matches(store=store_path, lists=["asns"])) == 2
    # A repeat within 15 minutes is served from the connector cache, so fail the call itself.
    from cyberau_cloudflare_radar import source

    failed = {"data": None, "warnings": ["upstream status 503"], "cache": "snapshot"}
    monkeypatch.setattr(source, "get_radar_bgp_hijacks_events", lambda **kwargs: failed)
    monkeypatch.setattr(source, "get_radar_bgp_leaks_events", lambda **kwargs: failed)
    summary = run_watchlist(store=store_path, radar=True, now="2026-10-18T10:00:00Z")
    assert summary["status"] == "ok"
    assert summary["radar"]["failed"] == 1
    assert any("Radar query failed" in item for item in summary["warnings"])
    assert len(list_matches(store=store_path, lists=["asns"])) == 2
    summary = run_watchlist(store=store_path, now="2026-10-30T10:00:00Z")
    assert summary["removed"] == 2
    assert list_matches(store=store_path, lists=["asns"]) == []


def test_lookups_follow_the_profile_config(store_path, crtsh, radar, tmp_path):
    crt_requests, _ = crtsh
    radar_requests, _ = radar
    _write(store_path)
    config = tmp_path / "config.yaml"
    config.write_text("mcp_servers:\n  crtsh: {enabled: false}\n", encoding="utf-8")
    summary = run_watchlist(
        store=store_path,
        crtsh=True,
        radar=True,
        profile_config=config,
        now="2026-10-17T10:00:00Z",
    )
    assert summary["crtsh"]["skipped"] == "crt.sh connector is off in config.yaml"
    assert summary["radar"]["skipped"] == "Cloudflare Radar connector is off in config.yaml"
    assert crt_requests == [] and radar_requests == []
    assert _audit_records(store_path) == []


def test_no_outbound_call_carries_watched_values_except_to_its_connector(
    store_path, crtsh, radar, tmp_path, capsys
):
    """Issue 62: domains go only to crt.sh, ASNs only to Radar, checked against the audit log."""
    crt_requests, _ = crtsh
    radar_requests, _ = radar
    _write(store_path)
    _indicator("ipv4", "192.0.2.10")
    _advisory("adv-1", "FortiOS flaw hits Example Brand")
    config = tmp_path / "config.yaml"
    config.write_text(RADAR_CONFIG, encoding="utf-8")
    code, payload = _cli(
        [
            "watchlist",
            "run",
            "--crtsh",
            "--radar",
            "--profile-config",
            str(config),
            "--path",
            str(store_path),
        ],
        capsys,
    )
    assert code == 0, payload
    assert payload["crtsh"]["queried"] == 1 and payload["radar"]["queried"] == 2

    watched = {
        "domains": ["example.com"],
        "asns": ["64496"],
        "others": [
            "Example Brand",
            "Example Vendor",
            "ExampleOS",
            "192.0.2",
            "2001:db8",
            "Fortinet",
        ],
    }
    seen = [(request, "crtsh") for request in crt_requests]
    seen += [(request, "radar") for request in radar_requests]
    assert {request.url.host for request, _ in seen} == {"crt.sh", "api.cloudflare.com"}
    for request, label in seen:
        sent = (
            str(request.url) + request.content.decode() + json.dumps(dict(request.headers))
        ).lower()
        assert not any(value.lower() in sent for value in watched["others"]), label
        if label == "crtsh":
            assert request.url.host == "crt.sh"
            assert "64496" not in sent
        else:
            assert request.url.host == "api.cloudflare.com"
            assert "example.com" not in sent

    # Every outbound call is in the audit log, and each logged call names only the
    # watched value meant for that connector.
    calls = [record for record in _audit_records(store_path) if record["event"] == "tool_call"]
    by_tool: dict[str, list[dict]] = {}
    for record in calls:
        by_tool.setdefault(record["tool"], []).append(record)
    assert set(by_tool) == {
        "crtsh_certs",
        "get_radar_bgp_hijacks_events",
        "get_radar_bgp_leaks_events",
    }
    assert len(by_tool["crtsh_certs"]) == len(crt_requests)
    radar_calls = by_tool["get_radar_bgp_hijacks_events"] + by_tool["get_radar_bgp_leaks_events"]
    assert len(radar_calls) == len(radar_requests)
    for record in calls:
        args = json.dumps(record["args_redacted"]).lower()
        assert not any(value.lower() in args for value in watched["others"])
        if record["tool"] == "crtsh_certs":
            assert record["args_redacted"]["domain"] == "example.com"
            assert "64496" not in args
        else:
            assert record["args_redacted"]["involved_asn"] == 64496
            assert "example.com" not in args
