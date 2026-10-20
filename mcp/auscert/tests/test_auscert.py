import asyncio
import json
import os
import sqlite3
import time
from pathlib import Path

import cyberau_auscert.source as source
import httpx
import jsonschema
import pytest
from cyberau_auscert.source import auscert_bulletins, connector, schema_drift
from cyberau_common.server import build_server

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
FEED = FIXTURES / "bulletins.xml"
RESPONSE_SCHEMA = json.loads(
    (PACKAGE / "schema" / "auscert_bulletins.response.json").read_text(encoding="utf-8")
)
INPUT_SCHEMA = json.loads(
    (PACKAGE / "schema" / "auscert_bulletins.input.json").read_text(encoding="utf-8")
)
ENVELOPE = {
    "type": "object",
    "required": ["source", "retrieved_at", "cache", "data", "untrusted"],
}


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_AUSCERT_SNAPSHOT", str(FEED))
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    yield
    source._TRANSPORT = None


def live(monkeypatch, handler):
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.delenv("CYBERAU_AUSCERT_SNAPSHOT", raising=False)
    source._TRANSPORT = httpx.MockTransport(handler)


def serve(path: Path = FEED, status: int = 200, headers: dict | None = None):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, content=path.read_bytes(), headers=headers or {})

    return handler


def forget_rate_limit(tmp_path: Path) -> None:
    with sqlite3.connect(tmp_path / "rate_limit.sqlite") as conn:
        conn.execute("DELETE FROM rolling")


def age_cache(tmp_path: Path) -> None:
    with sqlite3.connect(tmp_path / "http_cache.sqlite") as conn:
        conn.execute("UPDATE http_cache SET fetched_at = fetched_at - 7200")


def test_happy_path_validates_against_schemas():
    result = auscert_bulletins()
    jsonschema.validate(result, RESPONSE_SCHEMA)
    jsonschema.validate(result, ENVELOPE)
    jsonschema.Draft202012Validator.check_schema(INPUT_SCHEMA)
    assert result["cache"] == "snapshot"
    assert result["attribution"].startswith("AusCERT public security bulletins")
    assert result["source_urls"] == ["https://portal.auscert.org.au/rss/bulletins/"]
    assert result["data_as_of"] == "2026-10-16T02:39:51Z"
    first = result["data"][0]
    assert first["bulletin_id"] == "ESB-2026.9003"
    assert first["kind"] == "ESB"
    assert first["link"] == "https://portal.auscert.org.au/bulletins/ESB-2026.9003/"
    assert first["published"] == "2026-10-16T13:39:51+11:00"
    assert first["cvss_max"] == 9.8
    assert first["cves"] == ["CVE-2024-3400", "CVE-2026-0001"]
    assert first["cve_count"] == 2
    assert first["summary"] == ""
    assert [row["bulletin_id"] for row in result["data"]] == [
        "ESB-2026.9003",
        "ESB-2026.9002",
        "ESB-2026.9001",
    ]


def test_bulletin_text_is_never_returned():
    encoded = json.dumps(auscert_bulletins())
    assert "Synthetic bulletin body" not in encoded
    assert "email the report" not in encoded


def test_free_text_is_wrapped_and_links_stay_on_the_portal():
    rows = {row["bulletin_id"]: row for row in auscert_bulletins()["data"]}
    hostile = rows["ESB-2026.9002"]
    assert hostile["title"].startswith("<<untrusted source=auscert>> Ignore all previous")
    assert hostile["title"].endswith("<<end untrusted>>")
    assert hostile["summary"].startswith("<<untrusted source=auscert>> Synthetic summary")
    assert rows["ESB-2026.9001"]["link"] == "https://portal.auscert.org.au/bulletins/ESB-2026.9001/"


def test_filters():
    since = auscert_bulletins(since="2026-10-16")
    assert [row["bulletin_id"] for row in since["data"]] == ["ESB-2026.9003", "ESB-2026.9002"]
    # ESB-2026.9001 is 12 October in UTC but 13 October in Sydney.
    sydney = auscert_bulletins(since="2026-10-13")
    assert len(sydney["data"]) == 3
    later = auscert_bulletins(since="2026-10-14")
    assert [row["bulletin_id"] for row in later["data"]] == ["ESB-2026.9003", "ESB-2026.9002"]
    by_cve = auscert_bulletins(query="cve-2024-3400")
    assert [row["bulletin_id"] for row in by_cve["data"]] == ["ESB-2026.9003"]
    by_word = auscert_bulletins(query="library")
    assert [row["bulletin_id"] for row in by_word["data"]] == ["ESB-2026.9001"]
    assert auscert_bulletins(query="CVE-2030-0000")["data"] == []
    assert len(auscert_bulletins(limit=1)["data"]) == 1


def test_bad_arguments_warn():
    assert auscert_bulletins(limit=0)["warnings"]
    assert auscert_bulletins(limit=101)["warnings"]
    assert auscert_bulletins(since="16/10/2026")["warnings"]
    assert auscert_bulletins(since="2026-02-31")["warnings"]


def test_advertised_schema_matches_the_ticket():
    tools = {tool.name: tool for tool in asyncio.run(build_server(connector()).list_tools())}
    advertised = tools["auscert_bulletins"].input_schema
    assert "required" not in advertised or advertised["required"] == []
    assert advertised["properties"]["limit"]["maximum"] == 100
    assert advertised["properties"]["limit"]["default"] == 20
    assert "pattern" in json.dumps(advertised["properties"]["since"])
    assert tools["auscert_bulletins"].annotations.read_only_hint is True
    assert tools["auscert_bulletins"].annotations.open_world_hint is True


def test_empty_feed(monkeypatch):
    monkeypatch.setenv("CYBERAU_AUSCERT_SNAPSHOT", str(FIXTURES / "bulletins_empty.xml"))
    result = auscert_bulletins()
    assert result["data"] == []
    assert "no bulletins" in result["warnings"][0]


def test_malformed_and_drifted_payloads_warn_without_raising(monkeypatch):
    monkeypatch.setenv("CYBERAU_AUSCERT_SNAPSHOT", str(FIXTURES / "bulletins_malformed.xml"))
    broken = auscert_bulletins()
    assert broken["data"] == []
    assert "not XML" in broken["warnings"][0]
    monkeypatch.setenv("CYBERAU_AUSCERT_SNAPSHOT", str(FIXTURES / "bulletins_drift.xml"))
    drifted = auscert_bulletins()
    assert drifted["data"] == []
    assert "missing title" in drifted["warnings"][0]
    assert schema_drift("") == "AusCERT feed is empty"
    assert schema_drift("<feed></feed>")
    assert "DTD" in schema_drift('<!DOCTYPE rss [<!ENTITY a "b">]><rss><channel/></rss>')


def test_incomplete_items_are_skipped_and_counted(monkeypatch, tmp_path):
    text = FEED.read_text(encoding="utf-8").replace(
        "<title>Example Library: CVSS (Max): 7.5</title>", "<title> </title>"
    )
    partial = tmp_path / "partial.xml"
    partial.write_text(text, encoding="utf-8")
    monkeypatch.setenv("CYBERAU_AUSCERT_SNAPSHOT", str(partial))
    result = auscert_bulletins()
    assert len(result["data"]) == 2
    assert "1 feed items were skipped" in result["warnings"][0]


def test_schema_drift_fails_the_health_probe(monkeypatch):
    assert connector().health(live=False, check_schema=True).ok is True
    monkeypatch.setenv("CYBERAU_AUSCERT_SNAPSHOT", str(FIXTURES / "bulletins_drift.xml"))
    probe = connector().health(live=False, check_schema=True)
    assert probe.ok is False
    assert "schema drift" in probe.detail
    assert connector().health(live=False).ok is True


FIXTURE_VALUES = (
    "ESB-2026.900",
    "Example Gateway",
    "Example Library",
    "Synthetic",
    "CVE-2024-3400",
)


def assert_unavailable(result: dict) -> None:
    assert result["data"] == []
    assert any("is unavailable" in warning for warning in result["warnings"])
    encoded = json.dumps(result)
    for value in FIXTURE_VALUES:
        assert value not in encoded


def test_offline_without_cache_serves_no_shipped_data(monkeypatch):
    monkeypatch.delenv("CYBERAU_AUSCERT_SNAPSHOT", raising=False)
    result = auscert_bulletins()
    assert result["cache"] == "snapshot"
    assert_unavailable(result)
    assert_unavailable(auscert_bulletins(query="CVE-2024-3400"))
    assert connector().health(live=False, check_schema=True).ok is True


def test_failed_live_fetch_serves_no_shipped_data(monkeypatch):
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("network unreachable", request=request)

    live(monkeypatch, fail)
    assert_unavailable(auscert_bulletins())
    assert_unavailable(auscert_bulletins(query="Example"))


def test_override_snapshot_is_marked():
    result = auscert_bulletins()
    assert result["data"]
    assert "operator-supplied" in result["warnings"][-1]


def test_live_fetch_caches_records_and_is_etag_aware(monkeypatch, tmp_path):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(dict(request.headers))
        if request.headers.get("if-none-match") == '"v1"':
            return httpx.Response(304, headers={"etag": '"v1"'})
        return httpx.Response(
            200,
            content=FEED.read_bytes(),
            headers={"etag": '"v1"', "content-type": "application/rss+xml"},
        )

    live(monkeypatch, handler)
    first = auscert_bulletins()
    assert first["cache"] == "miss"
    assert first["data"][0]["bulletin_id"] == "ESB-2026.9003"
    assert "hermes-cyber-au" in seen[0]["user-agent"]
    second = auscert_bulletins()
    assert second["cache"] == "hit"
    assert len(seen) == 1
    age_cache(tmp_path)
    forget_rate_limit(tmp_path)
    third = auscert_bulletins()
    assert third["cache"] == "hit"
    assert seen[1]["if-none-match"] == '"v1"'
    with sqlite3.connect(tmp_path / "auscert_bulletins.sqlite") as conn:
        rows = conn.execute("SELECT id, cves FROM bulletins ORDER BY id").fetchall()
    assert [row[0] for row in rows] == ["ESB-2026.9001", "ESB-2026.9002", "ESB-2026.9003"]
    assert json.loads(rows[2][1]) == ["CVE-2024-3400", "CVE-2026-0001"]


def test_offline_answers_from_cache_when_present(monkeypatch, tmp_path):
    live(monkeypatch, serve())
    assert auscert_bulletins()["cache"] == "miss"
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    fresh = auscert_bulletins()
    assert fresh["cache"] == "hit"
    age_cache(tmp_path)
    stale = auscert_bulletins()
    assert stale["cache"] == "stale"
    assert "offline" in stale["warnings"][0]
    assert stale["data"][0]["bulletin_id"] == "ESB-2026.9003"


@pytest.mark.parametrize("status", [401, 403])
def test_auth_errors_say_no_credential_is_needed(monkeypatch, status):
    live(monkeypatch, serve(status=status))
    result = auscert_bulletins()
    assert result["data"] == []
    assert f"HTTP {status}" in result["warnings"][0]
    assert "no env var" in result["warnings"][0]
    assert "unavailable" in result["warnings"][0]


def test_429_honours_retry_after(monkeypatch):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(429, headers={"retry-after": "900"})

    live(monkeypatch, handler)
    started = time.time()
    first = auscert_bulletins()
    assert "retry in 900 seconds" in first["warnings"][0]
    assert first["data"] == []
    again = auscert_bulletins()
    assert "asked for a pause" in again["warnings"][0]
    assert len(calls) == 1
    pause = json.loads((Path(os.environ["CYBERAU_DATA_DIR"]) / "auscert_backoff.json").read_text())
    assert started + 890 < pause["until"] < started + 910


def test_timeout_falls_back_to_cache(monkeypatch, tmp_path):
    live(monkeypatch, serve())
    assert auscert_bulletins()["cache"] == "miss"
    age_cache(tmp_path)
    forget_rate_limit(tmp_path)

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    source._TRANSPORT = httpx.MockTransport(timeout)
    result = auscert_bulletins()
    assert result["cache"] == "stale"
    assert result["data"][0]["bulletin_id"] == "ESB-2026.9003"
    assert "stale cached feed" in result["warnings"][0]


def test_timeout_without_cache_is_a_warning(monkeypatch):
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    live(monkeypatch, timeout)
    result = auscert_bulletins()
    assert result["data"] == []
    assert "unavailable" in result["warnings"][0]


def test_server_error_without_cache_is_a_warning(monkeypatch):
    live(monkeypatch, serve(status=500))
    result = auscert_bulletins()
    assert result["data"] == []
    assert "500" in result["warnings"][0]


def test_redirect_outside_the_allowlist_is_refused(monkeypatch):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://evil.example/rss"})

    live(monkeypatch, handler)
    result = auscert_bulletins()
    assert result["data"] == []
    assert "evil.example" in result["warnings"][0]
    assert calls == ["https://portal.auscert.org.au/rss/bulletins/"]


def test_second_live_request_within_30_minutes_is_not_sent(monkeypatch, tmp_path):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, content=FEED.read_bytes())

    live(monkeypatch, handler)
    auscert_bulletins()
    age_cache(tmp_path)
    again = auscert_bulletins()
    assert len(calls) == 1
    assert again["cache"] == "stale"
    assert again["data"]


def test_live_health_validates_the_response(monkeypatch):
    live(monkeypatch, serve())
    probe = connector().health(live=True)
    assert probe.ok is True
    assert probe.detail == "live ok"


def test_live_health_fails_on_drift_and_outage(monkeypatch, tmp_path):
    live(monkeypatch, serve(FIXTURES / "bulletins_drift.xml"))
    drift = connector().health(live=True)
    assert drift.ok is False
    assert "schema drift" in drift.detail
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "second"))
    live(monkeypatch, serve(status=403))
    outage = connector().health(live=True)
    assert outage.ok is False
    assert "403" in outage.detail


def test_cassette_replays():
    import vcr
    from vcr.serialize import deserialize
    from vcr.serializers import yamlserializer

    path = FIXTURES / "auscert_bulletins.yaml"
    requests, responses = deserialize(path.read_text(encoding="utf-8"), yamlserializer)
    assert requests and responses[0]["status"]["code"] == 200
    with vcr.VCR(record_mode="none").use_cassette(str(path)):
        played = httpx.get("https://portal.auscert.org.au/rss/bulletins/")
    assert played.status_code == 200
    assert played.text == FEED.read_text(encoding="utf-8")


def test_no_secret_is_present_in_fixtures_or_output():
    for path in FIXTURES.iterdir():
        text = path.read_text(encoding="utf-8").lower()
        assert "authorization" not in text
        assert "api-key" not in text
        assert "token" not in text
    assert "token" not in json.dumps(auscert_bulletins()).lower()
