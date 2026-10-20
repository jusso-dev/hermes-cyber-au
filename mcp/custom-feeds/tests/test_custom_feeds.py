"""Custom feed tests. Every feed body is a synthetic fixture."""

import asyncio
import json
import time
from datetime import UTC, datetime
from pathlib import Path

import cyberau_custom_feeds.source as source
import httpx
import jsonschema
import pytest
import yaml
from cyberau_common.server import build_server
from cyberau_custom_feeds.config import Feed, available_packs, load_config, safe_feed_url
from cyberau_custom_feeds.source import (
    connector,
    custom_feed_items,
    custom_feed_list,
    filter_items,
    parse_feed,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 20, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.delenv("CYBERAU_WATCH_PACKS_DIR", raising=False)
    source._SLEEP = lambda _seconds: None
    source._LIMIT_SLEEP = lambda _seconds: None
    yield
    source._TRANSPORT = None
    source._SLEEP = time.sleep
    source._LIMIT_SLEEP = time.sleep


def _config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "data" / "watchlists.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _serve(bodies: dict[str, str], seen: list | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        body = bodies.get(str(request.url))
        if body is None:
            return httpx.Response(404, text="missing")
        return httpx.Response(200, text=body, headers={"content-type": "application/rss+xml"})

    source._TRANSPORT = httpx.MockTransport(handler)


def test_tools_are_read_only():
    listed = asyncio.run(build_server(connector()).list_tools())
    assert sorted(tool.name for tool in listed) == ["custom_feed_items", "custom_feed_list"]
    for tool in listed:
        assert tool.annotations.read_only_hint is True
        schema = json.loads((ROOT / "schema" / f"{tool.name}.input.json").read_text("utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)


def test_rss_parse_strips_markup_and_sorts_newest_first():
    items, problem = parse_feed(_fixture("custom_feed_items_rss.xml"))
    assert problem is None
    assert [item["published"] for item in items] == [
        "2026-10-19T20:23:15Z",
        "2026-10-19T10:00:00Z",
        "2023-01-01T00:00:00Z",
    ]
    first = items[0]
    assert first["categories"] == ["Security", "Features"]
    assert "<" not in first["summary"]
    assert first["url"] == "https://updates.example/item?id=900001"
    assert len(first["id"]) == 16


def test_atom_parse_drops_unsafe_links():
    items, problem = parse_feed(_fixture("custom_feed_items_atom.xml"))
    assert problem is None
    assert items[0]["title"] == "New Entra Conditional Access controls"
    assert items[0]["categories"] == ["Identity"]
    assert items[1]["url"] == ""


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (_fixture("custom_feed_items_dtd.xml"), "DTD"),
        ("not xml", "not XML"),
        ("<html><body/></html>", "neither RSS nor Atom"),
        ("", "empty"),
    ],
)
def test_unusable_feeds_are_refused(text, message):
    items, problem = parse_feed(text)
    assert items == []
    assert message in problem


def test_filters_by_category_term_and_age():
    items, _ = parse_feed(_fixture("custom_feed_items_rss.xml"))
    feed = Feed("azure", "Azure", "https://updates.example/rss", categories=("Security",))
    assert [item["id"] for item in filter_items(feed, items, now=NOW)] == [items[0]["id"]]
    old = Feed("azure", "Azure", "https://updates.example/rss", max_age_days=365 * 5)
    assert len(filter_items(old, items, now=NOW)) == 3
    terms = Feed("azure", "Azure", "https://updates.example/rss", include=("virtual machine",))
    assert [item["id"] for item in filter_items(terms, items, now=NOW)] == [items[1]["id"]]
    # Whole words only: "Defend" does not match "Defender".
    partial = Feed("azure", "Azure", "https://updates.example/rss", include=("Defend",))
    assert filter_items(partial, items, now=NOW) == []


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        ("https://vendor.example/feed.xml", True),
        ("http://vendor.example/feed.xml", False),
        ("https://192.0.2.10/feed.xml", False),
        ("https://vendor.example:8443/feed.xml", False),
        ("https://user:pass@vendor.example/feed.xml", False),
        ("https://localhost/feed.xml", False),
    ],
)
def test_feed_urls_must_be_https_dns_names(url, ok):
    assert safe_feed_url(url) is ok


def test_config_loads_packs_feeds_and_watches(tmp_path):
    path = _config(tmp_path, _fixture("custom_feed_list_watchlists.yaml"))
    config = load_config(path)
    assert config.packs == ("microsoft-security",)
    ids = [feed.id for feed in config.feeds]
    assert "msrc-update-guide" in ids and "vendor-blog" in ids
    assert {watch.name for watch in config.watches} == {"microsoft-security", "vendor-changes"}
    assert config.warnings == ()


def test_config_skips_bad_entries_without_echoing_them(tmp_path):
    path = _config(
        tmp_path,
        """
packs: [no-such-pack, "Bad Name"]
feeds:
  - id: private-feed
    url: http://10.0.0.5/secret-feed
  - id: ok-feed
    url: https://vendor.example/feed.xml
  - id: ok-feed
    url: https://vendor.example/other.xml
watches:
  - name: no-terms
    sources: [ok-feed]
  - name: unknown-source
    sources: [missing-feed]
    any: [x]
""",
    )
    config = load_config(path)
    assert [feed.id for feed in config.feeds] == ["ok-feed"]
    assert [watch.name for watch in config.watches] == ["unknown-source"]
    text = " ".join(config.warnings)
    assert "10.0.0.5" not in text
    assert "pack no-such-pack is not available" in text
    assert "packs entry 2" in text
    assert "feed ok-feed is defined twice" in text
    assert "missing-feed" in text


def test_shipped_pack_is_valid_and_https():
    assert "microsoft-security" in available_packs()
    pack = yaml.safe_load((ROOT / "packs" / "microsoft-security.yaml").read_text("utf-8"))
    allow = yaml.safe_load((ROOT.parent / "egress-allowlist.yaml").read_text("utf-8"))
    hosts = set(allow["connectors"]["custom-feeds"]["hosts"])
    for feed in pack["feeds"]:
        assert safe_feed_url(feed["url"]), feed["id"]
        assert Feed(feed["id"], feed["id"], feed["url"]).host in hosts, feed["id"]


def test_list_and_items_tools(tmp_path):
    _config(
        tmp_path,
        """
feeds:
  - id: azure
    url: https://updates.example/rss
    categories: [Security]
""",
    )
    listed = custom_feed_list()
    jsonschema.validate(
        listed["data"], json.loads((ROOT / "schema/custom_feed_list.response.json").read_text())
    )
    assert listed["data"]["feeds"][0]["id"] == "azure"

    seen: list[httpx.Request] = []
    _serve({"https://updates.example/rss": _fixture("custom_feed_items_rss.xml")}, seen)
    items = custom_feed_items("azure", limit=5)
    schema = json.loads((ROOT / "schema/custom_feed_items.response.json").read_text())
    jsonschema.validate(items["data"], schema)
    assert items["untrusted"] is True
    row = items["data"]["items"][0]
    assert row["title"].startswith("<<untrusted source=custom-feeds>>")
    assert "Ignore previous instructions" in row["summary"]
    assert row["summary"].startswith("<<untrusted")
    assert seen[0].url.host == "updates.example"

    unknown = custom_feed_items("nope")
    assert unknown["data"] is None
    assert "not configured" in unknown["warnings"][0]


def test_failed_fetch_serves_stale_then_reports(tmp_path):
    _config(tmp_path, "feeds:\n  - id: azure\n    url: https://updates.example/rss\n")
    _serve({"https://updates.example/rss": _fixture("custom_feed_items_rss.xml")})
    first = custom_feed_items("azure")
    assert first["cache"] == "miss"

    def down(_request):
        raise httpx.ConnectError("down")

    source._TRANSPORT = httpx.MockTransport(down)
    source._TTL, ttl = 0, source._TTL
    try:
        stale = custom_feed_items("azure")
    finally:
        source._TTL = ttl
    assert stale["cache"] in {"stale", "hit"}
    assert stale["data"]["items"]


def test_health(tmp_path):
    assert connector().health(live=False).ok is True
    assert "no feeds" in connector().health(live=True).detail
    _config(tmp_path, "feeds:\n  - id: azure\n    url: https://updates.example/rss\n")
    _serve({"https://updates.example/rss": _fixture("custom_feed_items_rss.xml")})
    assert connector().health(live=True).ok is True
    _serve({})
    probe = connector().health(live=True)
    assert probe.ok is False and "azure" in probe.detail
