import json
import shutil
import time
from pathlib import Path

import cyberau_asd_acsc.source as source
import httpx
import pytest
from cyberau_asd_acsc.source import (
    asd_feed_status,
    asd_get_item,
    asd_list_items,
    asd_search,
    connector,
    import_feed,
    schema_drift,
)
from cyberau_common.cache import HttpCache
from cyberau_common.server import build_server

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ITEM = "https://www.cyber.gov.au/about-this-advisory"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_ASD_SNAPSHOT", str(FIXTURES))
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    source._SLEEP = lambda _seconds: None
    yield
    source._TRANSPORT = None
    source._SLEEP = time.sleep


def test_list_newest_first_and_attribution():
    listed = asd_list_items()
    assert listed["attribution"].startswith("Commonwealth of Australia")
    assert listed["data"][0]["link"] == ITEM
    assert listed["data"][0]["published"] == "2026-10-15"
    assert "CVE-2024-3400" in listed["data"][0]["cves"]
    assert "<<untrusted source=asd>>" in listed["data"][0]["title"]
    assert any("Older synthetic alert" in row["title"] for row in listed["data"])


def test_since_uses_sydney_dates():
    later = asd_list_items(feeds=["alerts"], since="2024-04-12", limit=10)
    assert [row["published"] for row in later["data"]] == ["2026-10-15"]
    both = asd_list_items(feeds=["alerts"], since="2024-04-11", limit=10)
    assert len(both["data"]) == 2
    assert asd_list_items(limit=0)["warnings"]


def test_empty_and_malformed(tmp_path, monkeypatch):
    empty = tmp_path / "empty"
    empty.mkdir()
    for name in ("alerts", "advisories", "publications", "threats", "news"):
        target = empty / f"{name}.xml"
        source_file = FIXTURES / ("rss_empty.xml" if name == "alerts" else f"{name}.xml")
        shutil.copy(source_file, target)
    monkeypatch.setenv("CYBERAU_ASD_SNAPSHOT", str(empty))
    listed = asd_list_items(feeds=["alerts"])
    assert listed["data"] == []
    assert "no items" in listed["warnings"][0]
    broken = tmp_path / "broken"
    broken.mkdir()
    shutil.copy(FIXTURES / "rss_malformed.xml", broken / "alerts.xml")
    monkeypatch.setenv("CYBERAU_ASD_SNAPSHOT", str(broken))
    warned = asd_list_items(feeds=["alerts"])
    assert warned["warnings"]
    assert schema_drift("<feed></feed>")


def test_get_item_extracts_ids():
    page = asd_get_item(ITEM)
    assert page["data"]["cves"] == ["CVE-2024-3400"]
    assert page["data"]["attack_ids"] == ["T1566.001"]
    assert "<<untrusted source=asd>>" in page["data"]["body"]
    assert page["data"]["links"] == ["https://www.cyber.gov.au/rss/alerts"]
    missing = asd_get_item("https://www.cyber.gov.au/missing")
    assert missing["warnings"]
    rejected = asd_get_item("https://example.com/nope")
    assert rejected["warnings"]


def test_search_keeps_items_that_leave_the_feed(tmp_path, monkeypatch):
    asd_list_items(feeds=["alerts"])
    later = tmp_path / "later"
    later.mkdir()
    text = (FIXTURES / "alerts.xml").read_text(encoding="utf-8")
    kept = text.replace(
        """    <item>
      <title>Older synthetic alert</title>
      <link>https://www.cyber.gov.au/about-older-alert</link>
      <pubDate>Thu, 11 Apr 2024 23:30:00 +1000</pubDate>
      <description>Older item that can drop out of a later window.</description>
    </item>
""",
        "",
    )
    (later / "alerts.xml").write_text(kept, encoding="utf-8")
    monkeypatch.setenv("CYBERAU_ASD_SNAPSHOT", str(later))
    current = asd_list_items(feeds=["alerts"])
    assert [row["link"] for row in current["data"]] == [ITEM]
    found = asd_search("Older synthetic")
    assert found["data"][0]["link"] == "https://www.cyber.gov.au/about-older-alert"
    by_cve = asd_search("CVE-2024-3400")
    assert by_cve["data"][0]["cves"] == ["CVE-2024-3400"]


def test_fallback_ladder_names_the_feed(tmp_path, monkeypatch):
    asd_list_items(feeds=["alerts"])
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_ASD_SNAPSHOT")

    def fail(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("timed out")

    source._TRANSPORT = httpx.MockTransport(fail)
    listed = asd_list_items(feeds=["alerts"])
    assert listed["cache"] == "stale"
    assert listed["data"]
    assert "alerts" in listed["warnings"][0]
    status = asd_feed_status(feeds=["alerts"])
    assert status["data"][0]["method"] == "stale"
    assert status["data"][0]["item_count"] == 2
    untouched = tmp_path / "unused"
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(untouched))
    source._TRANSPORT = httpx.MockTransport(
        lambda _request: httpx.Response(500, content=(FIXTURES / "http_500.txt").read_bytes())
    )
    failed = asd_list_items(feeds=["alerts"])
    assert failed["cache"] == "snapshot"
    assert "served shipped snapshot" in failed["warnings"][0]
    assert "alerts" in failed["warnings"][0]

    def http11(request: httpx.Request) -> httpx.Response:
        if "HTTP/1.1 fallback" not in request.headers.get("user-agent", ""):
            raise httpx.ConnectError("connection reset")
        assert "hermes-cyber-au" in request.headers.get("user-agent", "")
        return httpx.Response(200, content=(FIXTURES / "alerts.xml").read_bytes())

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "http11"))
    source._TRANSPORT = httpx.MockTransport(http11)
    recovered = asd_list_items(feeds=["alerts"])
    assert recovered["data"]
    assert asd_feed_status(feeds=["alerts"])["data"][0]["method"] == "http11"


def test_schema_and_live_health(tmp_path, monkeypatch):
    listed = asyncio_tools()
    encoded = json.dumps(listed["asd_list_items"].inputSchema)
    assert "alerts" in encoded
    assert "maximum" in encoded
    assert listed["asd_get_item"].inputSchema["required"] == ["url"]
    assert listed["asd_search"].inputSchema["required"] == ["query"]
    probe = connector().health(live=False, check_schema=True)
    monkeypatch.setenv("CYBERAU_ASD_SNAPSHOT", str(FIXTURES / "drift"))
    failed = connector().health(live=False, check_schema=True)
    assert probe.ok is True
    assert failed.ok is False

    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_ASD_SNAPSHOT")
    body = (FIXTURES / "alerts.xml").read_bytes()
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    key = cache.key("GET", "https://www.cyber.gov.au/rss/alerts", None, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=body, ttl=86400)
    calls = {"n": 0}

    def ok(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(ok)
    live = connector().health(live=True)
    assert calls["n"] == 1
    assert live.ok is True

    def unavailable(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503, content=b"unavailable")

    calls["n"] = 0
    source._TRANSPORT = httpx.MockTransport(unavailable)
    down = connector().health(live=True)
    assert calls["n"] >= 1
    assert down.ok is False
    assert "503" in down.detail


def test_redirect_and_retry(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_ASD_SNAPSHOT")

    def redirect(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/stolen"})

    source._TRANSPORT = httpx.MockTransport(redirect)
    refused = asd_list_items(feeds=["alerts"])
    assert refused["warnings"]
    assert "evil.example" in refused["warnings"][0] or "allow" in refused["warnings"][0].lower()

    calls = {"n": 0}
    body = (FIXTURES / "alerts.xml").read_bytes()

    def retry(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "0"})
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(retry)
    listed = asd_list_items(feeds=["alerts"])
    assert listed["data"][0]["cves"] == ["CVE-2024-3400"]
    assert calls["n"] >= 2


def test_import_and_status():
    assert "imported 2 alerts" in import_feed(str(FIXTURES / "alerts.xml"), "alerts")
    status = asd_feed_status(feeds=["alerts"])
    assert status["data"][0]["method"] == "manual"
    assert status["data"][0]["item_count"] == 2
    from cyberau_common.cli import main

    imported = main(
        ["import", "asd", str(FIXTURES / "rss_advisories.xml"), "--feed", "advisories"]
    )
    assert imported == 0
    assert main(["import", "nope", "missing.xml"]) == 2


def test_offline_prefers_stored_poll_over_shipped_snapshot(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_ASD_SNAPSHOT")
    unique = """<?xml version="1.0"?>
<rss version="2.0"><channel><item>
<title>Unique live alert</title>
<link>https://www.cyber.gov.au/unique-live-alert</link>
<pubDate>Thu, 15 Oct 2026 09:00:00 +1100</pubDate>
<description>Only on the live feed.</description>
</item></channel></rss>"""
    source._TRANSPORT = httpx.MockTransport(
        lambda _request: httpx.Response(200, content=unique.encode())
    )
    live = asd_list_items(feeds=["alerts"])
    assert live["data"][0]["link"].endswith("/unique-live-alert")
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    source._TRANSPORT = None
    offline = asd_list_items(feeds=["alerts"])
    assert [row["link"] for row in offline["data"]] == [
        "https://www.cyber.gov.au/unique-live-alert"
    ]


def test_offline_uses_http_cache_before_shipped_snapshot(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.delenv("CYBERAU_ASD_SNAPSHOT")
    body = """<?xml version="1.0"?>
<rss version="2.0"><channel><item>
<title>Cached live alert</title>
<link>https://www.cyber.gov.au/cached-live-alert</link>
<pubDate>Thu, 15 Oct 2026 09:00:00 +1100</pubDate>
<description>Served from the HTTP cache.</description>
</item></channel></rss>"""
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    key = cache.key("GET", "https://www.cyber.gov.au/rss/alerts", None, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=body.encode(), ttl=900)
    listed = asd_list_items(feeds=["alerts"])
    assert listed["data"][0]["link"].endswith("/cached-live-alert")


def test_malformed_live_feed_uses_stored_poll(monkeypatch):
    asd_list_items(feeds=["alerts"])
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_ASD_SNAPSHOT")
    html = b"<html><body>cdn error</body></html>"
    source._TRANSPORT = httpx.MockTransport(lambda _request: httpx.Response(200, content=html))
    listed = asd_list_items(feeds=["alerts"])
    assert listed["cache"] == "stale"
    assert any(row["link"] == ITEM for row in listed["data"])
    assert "alerts" in listed["warnings"][0]


def test_get_item_keeps_fallback_page(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_ASD_SNAPSHOT")
    source._TRANSPORT = httpx.MockTransport(
        lambda _request: (_ for _ in ()).throw(httpx.ConnectError("timed out"))
    )
    page = asd_get_item(ITEM)
    assert page["data"]["cves"] == ["CVE-2024-3400"]
    assert page["warnings"]
    assert page["data"] is not None


def test_page_fetch_does_not_drop_dated_advisory(monkeypatch):
    listed = asd_list_items(feeds=["advisories"])
    link = listed["data"][0]["link"]
    published = listed["data"][0]["published"]
    assert asd_search("vendor", since=published)["data"]
    method = asd_feed_status(feeds=["advisories"])["data"][0]["method"]
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_ASD_SNAPSHOT")
    html = (FIXTURES / "item_advisory.html").read_bytes()
    source._TRANSPORT = httpx.MockTransport(lambda _request: httpx.Response(200, content=html))
    fetched = asd_get_item(link)
    assert fetched["data"]["body"]
    assert asd_search("vendor", since=published)["data"][0]["link"] == link
    assert asd_feed_status(feeds=["advisories"])["data"][0]["method"] == method


def test_bad_pubdate_falls_back(monkeypatch):
    asd_list_items(feeds=["alerts"])
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_ASD_SNAPSHOT")
    bad = """<?xml version="1.0"?>
<rss version="2.0"><channel><item>
<title>Broken date</title>
<link>https://www.cyber.gov.au/broken-date</link>
<pubDate>not-a-date</pubDate>
<description>Broken.</description>
</item></channel></rss>"""
    source._TRANSPORT = httpx.MockTransport(
        lambda _request: httpx.Response(200, content=bad.encode())
    )
    listed = asd_list_items(feeds=["alerts"])
    assert "pubDate" in listed["warnings"][0]
    assert any(row["link"] == ITEM for row in listed["data"])
    assert source._published("not-a-date") == ""


def test_cassettes_replay():
    import vcr
    from vcr.serialize import deserialize
    from vcr.serializers import yamlserializer

    player = vcr.VCR(record_mode="none")
    for name, uri in {
        "asd_list_items": "https://www.cyber.gov.au/rss/alerts",
        "asd_get_item": ITEM,
    }.items():
        path = FIXTURES / f"{name}.yaml"
        requests, responses = deserialize(path.read_text(encoding="utf-8"), yamlserializer)
        assert requests and responses[0]["status"]["code"] == 200
        with player.use_cassette(str(path)):
            played = httpx.get(uri)
        assert played.status_code == 200


def asyncio_tools():
    import asyncio

    listed = asyncio.run(build_server(connector()).list_tools())
    return {tool.name: tool for tool in listed}
