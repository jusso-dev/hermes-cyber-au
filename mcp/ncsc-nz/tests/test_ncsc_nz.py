import asyncio
import ipaddress
import json
import shutil
import sqlite3
import time
from pathlib import Path

import cyberau_ncsc_nz.source as source
import httpx
import jsonschema
import pytest
from cyberau_common.cache import HttpCache
from cyberau_common.cli import main
from cyberau_common.server import build_server

FIXTURES = Path(__file__).resolve().parent / "fixtures"
EDGE = "https://www.ncsc.govt.nz/alerts/synthetic-edge-device/"
DATED = "https://www.ncsc.govt.nz/alerts/synthetic-dated/"
UNDATED = "https://www.ncsc.govt.nz/alerts/synthetic-undated/"
REPEATED = "https://www.ncsc.govt.nz/alerts/repeated-synthetic-alert/"
ENVELOPE = {
    "type": "object",
    "required": ["source", "retrieved_at", "cache", "data", "untrusted", "attribution"],
    "properties": {
        "source": {"type": "string"},
        "retrieved_at": {"type": "string"},
        "cache": {"enum": ["hit", "miss", "stale", "snapshot"]},
        "attribution": {"type": "string"},
        "untrusted": {"const": True},
        "warnings": {"type": "array", "items": {"type": "string"}},
        "data": {},
    },
}


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_NCSC_SNAPSHOT", str(FIXTURES))
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    source._SLEEP = lambda _seconds: None
    source._RESOLVER = lambda _host: [ipaddress.ip_address("1.1.1.1")]
    source._TRANSPORT = None
    yield
    source._TRANSPORT = None
    source._SLEEP = time.sleep
    source._RESOLVER = None


def _schema(name: str) -> dict:
    path = Path(__file__).resolve().parents[1] / "schema" / name
    return json.loads(path.read_text(encoding="utf-8"))


def _use_list(monkeypatch, tmp_path, filename: str) -> None:
    snap = tmp_path / "snap" / filename
    snap.mkdir(parents=True)
    shutil.copy(FIXTURES / filename, snap / "alerts_page.html")
    monkeypatch.setenv("CYBERAU_NCSC_SNAPSHOT", str(snap))


def _live(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_NCSC_SNAPSHOT")


def test_list_orders_dates_and_wraps_text():
    listed = source.ncscnz_list_alerts()
    jsonschema.validate(listed, ENVELOPE)
    jsonschema.validate(listed["data"], _schema("ncscnz_list_alerts.response.json"))
    assert listed["attribution"].startswith("NCSC NZ")
    assert listed["cache"] == "snapshot"
    assert [row["link"] for row in listed["data"]] == [
        EDGE,
        "https://www.ncsc.govt.nz/alerts/older-synthetic-alert/",
        "https://www.ncsc.govt.nz/alerts/undated-synthetic-alert/",
    ]
    assert listed["data"][0]["published"] == "2026-10-15"
    assert listed["data"][0]["cves"] == ["CVE-2024-3400"]
    assert "<<untrusted source=ncscnz>>" in listed["data"][0]["title"]
    assert "\u202e" not in listed["data"][0]["title"]
    assert listed["data"][2]["published"] == ""
    assert listed["data_as_of"] == "2026-10-15"


def test_since_is_inclusive_sydney_date_and_skips_undated():
    later = source.ncscnz_list_alerts(since="2026-10-15", limit=10)
    assert [row["link"] for row in later["data"]] == [EDGE]
    both = source.ncscnz_list_alerts(since="2024-04-11")
    assert len(both["data"]) == 2
    assert source.ncscnz_list_alerts(limit=0)["warnings"]
    assert source.ncscnz_list_alerts(since="yesterday")["warnings"]
    assert source.ncscnz_list_alerts(limit=101)["warnings"]


def test_updated_alerts_dedupe_by_url(tmp_path, monkeypatch):
    _use_list(monkeypatch, tmp_path, "alert_updated_repeat.html")
    listed = source.ncscnz_list_alerts()
    links = [row["link"] for row in listed["data"]]
    assert links.count(REPEATED) == 1
    assert len(listed["data"]) == 2
    repeated = next(row for row in listed["data"] if row["link"] == REPEATED)
    assert "UPDATED:" in repeated["title"]


def test_empty_and_malformed_warn(tmp_path, monkeypatch):
    _use_list(monkeypatch, tmp_path, "alerts_empty.html")
    empty = source.ncscnz_list_alerts()
    assert empty["data"] == []
    assert "no NCSC NZ alerts matched" in empty["warnings"][0]
    _use_list(monkeypatch, tmp_path, "alerts_malformed.html")
    broken = source.ncscnz_list_alerts()
    assert broken["data"] == []
    assert broken["warnings"]
    assert "drift" in broken["warnings"][0]


def test_get_alert_quotes_a_short_passage_and_keeps_later_cves():
    page = source.ncscnz_get_alert(DATED)
    jsonschema.validate(page, ENVELOPE)
    jsonschema.validate(page["data"], _schema("ncscnz_get_alert.response.json"))
    assert page["data"]["published"] == "2025-10-29"
    assert page["data"]["cves"] == ["CVE-2024-3400", "CVE-2025-0001"]
    assert "CVE-2024-3400" in page["data"]["passage"]
    assert "Later synthetic" not in page["data"]["passage"]
    assert "CVE-2099-9999" not in page["data"]["passage"]
    assert "CVE-2099-9999" not in page["data"]["cves"]
    assert page["data"]["passage"].count("<<untrusted source=ncscnz>>") == 1
    missing_date = source.ncscnz_get_alert(UNDATED)
    assert missing_date["data"]["published"] == ""
    assert "Synthetic alert without a date" in missing_date["data"]["title"]
    rejected = source.ncscnz_get_alert("https://example.com/nope")
    assert rejected["warnings"]
    assert rejected["attribution"].startswith("NCSC NZ")


def test_clock_time_converts_to_sydney_date(tmp_path, monkeypatch):
    snap = tmp_path / "item"
    snap.mkdir()
    (snap / "midnight.html").write_text(
        """
        <p class="content__detail content__detail--date">12:30am, 29 October 2025</p>
        <h1 class="content-intro__title">
        <span class="content-intro__title--eng">Midnight</span>
        </h1>
        <div class="advisory-page-intro"><p>Synthetic early morning passage.</p></div>
        """,
        encoding="utf-8",
    )
    (snap / "items.json").write_text(
        json.dumps({"https://www.ncsc.govt.nz/alerts/midnight/": "midnight.html"}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_NCSC_SNAPSHOT", str(snap))
    page = source.ncscnz_get_alert("https://www.ncsc.govt.nz/alerts/midnight/")
    assert page["data"]["published"] == "2025-10-28"


def test_history_keeps_alerts_that_leave_the_list(tmp_path, monkeypatch):
    listed = source.ncscnz_list_alerts()
    assert any(row["link"] == EDGE for row in listed["data"])
    snap = tmp_path / "later"
    snap.mkdir()
    (snap / "alerts_page.html").write_text(
        """
        <div class="explore explore--alert">
        <a href="/alerts/older-synthetic-alert/" class="card__link">
        <article class="card card--alert">
        <h3 class="card__title">Older synthetic alert</h3>
        <p class="card__date">11 April 2024</p>
        </article></a></div>
        """,
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_NCSC_SNAPSHOT", str(snap))
    current = source.ncscnz_list_alerts()
    assert [row["link"] for row in current["data"]] == [
        "https://www.ncsc.govt.nz/alerts/older-synthetic-alert/"
    ]
    kept = source.ncscnz_get_alert(EDGE)
    assert kept["cache"] == "stale"
    assert "edge device" in kept["data"]["title"]
    assert kept["data"]["cves"] == ["CVE-2024-3400"]
    with sqlite3.connect(tmp_path / "ncsc_alerts.sqlite") as conn:
        count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    assert count >= 2


def test_bidi_is_stripped(tmp_path, monkeypatch):
    snap = tmp_path / "bidi"
    snap.mkdir()
    (snap / "alerts_page.html").write_text(
        """
        <div class="explore explore--alert">
        <a href="/alerts/bidi-synthetic/" class="card__link">
        <article class="card card--alert">
        <h3 class="card__title">Synthetic \u202e title</h3>
        <p class="card__date">1 January 2026</p>
        </article></a></div>
        """,
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_NCSC_SNAPSHOT", str(snap))
    listed = source.ncscnz_list_alerts()
    assert "\u202e" not in listed["data"][0]["title"]
    assert "<<untrusted source=ncscnz>>" in listed["data"][0]["title"]


def test_schema_drift_fails_health_when_a_field_is_renamed(monkeypatch):
    ok = source.connector().health(live=False, check_schema=True)
    monkeypatch.setenv("CYBERAU_NCSC_SNAPSHOT", str(FIXTURES / "drift"))
    failed = source.connector().health(live=False, check_schema=True)
    assert ok.ok is True
    assert failed.ok is False
    assert "card__title" in failed.detail
    assert schema_drift_message()
    assert main(["health", "ncsc-nz", "--schema-drift"]) == 1


def schema_drift_message() -> str:
    text = (FIXTURES / "drift" / "alerts_page.html").read_text(encoding="utf-8")
    return source.schema_drift(text) or ""


def test_input_schemas_match_the_tools():
    listed = asyncio.run(build_server(source.connector()).list_tools())
    tools = {tool.name: tool for tool in listed}
    assert tools["ncscnz_list_alerts"].annotations.readOnlyHint is True
    assert tools["ncscnz_get_alert"].annotations.openWorldHint is True
    encoded = json.dumps(tools["ncscnz_list_alerts"].inputSchema)
    assert "maximum" in encoded
    assert tools["ncscnz_get_alert"].inputSchema["required"] == ["url"]
    list_schema = _schema("ncscnz_list_alerts.input.json")
    get_schema = _schema("ncscnz_get_alert.input.json")
    jsonschema.Draft202012Validator.check_schema(list_schema)
    jsonschema.Draft202012Validator.check_schema(get_schema)
    jsonschema.validate({"since": "2026-10-15", "limit": 20}, list_schema)
    jsonschema.validate({"url": DATED}, get_schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"url": "https://example.com/nope"}, get_schema)


def test_auth_status_names_the_missing_credential(monkeypatch):
    _live(monkeypatch)
    for status in (401, 403):
        source._TRANSPORT = httpx.MockTransport(
            lambda _request, status=status: httpx.Response(status, content=b"no")
        )
        warned = source.ncscnz_list_alerts()
        assert warned["data"] == []
        assert str(status) in warned["warnings"][0]
        assert "env var" in warned["warnings"][0]
        _clear_rate_db()


def test_retry_after_is_honoured(monkeypatch):
    _live(monkeypatch)
    body = (FIXTURES / "alerts_page.html").read_bytes()
    calls = {"n": 0}
    slept: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "7"})
        return httpx.Response(200, content=body)

    source._SLEEP = lambda seconds: slept.append(seconds)
    source._TRANSPORT = httpx.MockTransport(handler)
    listed = source.ncscnz_list_alerts()
    assert listed["data"][0]["cves"] == ["CVE-2024-3400"]
    assert calls["n"] >= 2
    assert 7.0 in slept


def test_timeout_falls_back_to_cache(tmp_path, monkeypatch):
    _live(monkeypatch)
    body = (FIXTURES / "alerts_page.html").read_text(encoding="utf-8")
    body = body.replace("Synthetic edge device alert", "Cached synthetic alert")
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    key = cache.key("GET", source.LIST_URL, None, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=body.encode(), ttl=0)

    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    source._TRANSPORT = httpx.MockTransport(handler)
    listed = source.ncscnz_list_alerts()
    assert listed["cache"] == "stale"
    assert "Cached synthetic alert" in listed["data"][0]["title"]
    assert "cache" in listed["warnings"][0]


def test_redirect_off_allowlist_is_refused(monkeypatch):
    _live(monkeypatch)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/stolen"})

    source._TRANSPORT = httpx.MockTransport(handler)
    refused = source.ncscnz_list_alerts()
    assert refused["warnings"]
    assert "evil.example" in refused["warnings"][0]


def test_offline_prefers_cache_over_the_operator_snapshot(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_NCSC_SNAPSHOT")
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    body = (FIXTURES / "alerts_page.html").read_text(encoding="utf-8")
    body = body.replace("Synthetic edge device alert", "Cached offline alert")
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    key = cache.key("GET", source.LIST_URL, None, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=body.encode(), ttl=3600)
    listed = source.ncscnz_list_alerts()
    assert listed["cache"] == "stale"
    assert "Cached offline alert" in listed["data"][0]["title"]


def test_offline_without_cache_or_snapshot_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_NCSC_SNAPSHOT")
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    empty = tmp_path / "empty-data"
    empty.mkdir()
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(empty))
    missing = source.ncscnz_list_alerts()
    assert missing["data"] == []
    assert "unavailable" in missing["warnings"][0]


def test_live_health_checks_the_list_once(monkeypatch):
    _live(monkeypatch)
    body = (FIXTURES / "alerts_page.html").read_bytes()
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(handler)
    probe = source.connector().health(live=True)
    assert calls["n"] == 1
    assert probe.ok is True

    def drifted(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>no list</html>")

    source._TRANSPORT = httpx.MockTransport(drifted)
    _clear_rate_db()
    failed = source.connector().health(live=True)
    assert failed.ok is False


def test_fresh_cache_skips_a_second_fetch(monkeypatch):
    _live(monkeypatch)
    body = (FIXTURES / "alerts_page.html").read_bytes()
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(handler)
    first = source.ncscnz_list_alerts()
    second = source.ncscnz_list_alerts()
    assert first["cache"] == "miss"
    assert second["cache"] == "hit"
    assert calls["n"] == 1


def _clear_rate_db() -> None:
    for name in ("rate_limit.sqlite", "rate_limit.sqlite-wal", "rate_limit.sqlite-shm"):
        path = source._data_dir() / name
        if path.exists():
            path.unlink()


def test_card_without_a_link_does_not_borrow_the_previous_link():
    parser = source._ListParser()
    parser.feed(
        """
        <div class="explore--alert">
        <a class="card__link" href="/alerts/first/"><article class="card--alert">
        <h3 class="card__title">First</h3><p class="card__date">1 January 2026</p>
        </article></a>
        <article class="card--alert">
        <h3 class="card__title">Linkless</h3><p class="card__date">2 January 2026</p>
        </article>
        <article class="card--alert"><a class="card__link" href="/alerts/inside/">
        <h3 class="card__title">Inside</h3></a><p class="card__date">3 January 2026</p>
        </article></div>
        """
    )
    assert [item["link"] for item in parser.items] == [
        "https://www.ncsc.govt.nz/alerts/first/",
        "https://www.ncsc.govt.nz/alerts/inside/",
    ]


def _serve_live(monkeypatch) -> None:
    _live(monkeypatch)
    listed = (FIXTURES / "alerts_page.html").read_bytes()
    item = (FIXTURES / "alert_item.html").read_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        body = item if "synthetic-edge-device" in request.url.path else listed
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(handler)


def test_alert_url_without_a_trailing_slash_is_stored_once(tmp_path, monkeypatch):
    _serve_live(monkeypatch)
    source.ncscnz_list_alerts()
    page = source.ncscnz_get_alert(EDGE.rstrip("/"))
    assert page["data"]["url"] == EDGE
    with sqlite3.connect(tmp_path / "ncsc_alerts.sqlite") as conn:
        links = [row[0] for row in conn.execute("SELECT link FROM alerts")]
    assert links.count(EDGE) == 1
    assert EDGE.rstrip("/") not in links


def test_relisting_keeps_cves_found_on_the_alert_page(tmp_path, monkeypatch):
    _serve_live(monkeypatch)
    source.ncscnz_list_alerts()
    source.ncscnz_get_alert(EDGE)
    _clear_rate_db()
    (tmp_path / "http_cache.sqlite").unlink()
    source.ncscnz_list_alerts()
    with sqlite3.connect(tmp_path / "ncsc_alerts.sqlite") as conn:
        row = conn.execute("SELECT cves FROM alerts WHERE link = ?", (EDGE,)).fetchone()
    assert json.loads(row[0]) == ["CVE-2024-3400", "CVE-2025-0001"]


def test_requests_stay_on_http_1_1(monkeypatch):
    _serve_live(monkeypatch)
    seen = []
    real = httpx.Client

    def spy(*args, **kwargs):
        seen.append(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", spy)
    source.ncscnz_list_alerts()
    assert seen
    assert not any(kwargs.get("http2") for kwargs in seen)


def test_live_health_fails_when_the_rate_limit_message_is_blank(monkeypatch):
    _serve_live(monkeypatch)

    def refuse(*_args, **_kwargs):
        raise RuntimeError("")

    monkeypatch.setattr(source, "_limit", refuse)
    assert source.connector().health(live=True).ok is False


FIXTURE_VALUES = ("Synthetic", "synthetic", "Repeated", "CVE-2024-3400", "CVE-2025-0001")


def _assert_unavailable(result: dict, empty) -> None:
    assert result["data"] == empty
    assert any("is unavailable" in warning for warning in result["warnings"])
    encoded = json.dumps(result["data"]) + json.dumps(result["warnings"])
    for value in FIXTURE_VALUES:
        assert value not in encoded


def _all_tools_unavailable() -> None:
    _assert_unavailable(source.ncscnz_list_alerts(), [])
    for url in (EDGE, DATED, UNDATED, REPEATED):
        _assert_unavailable(source.ncscnz_get_alert(url), None)


def test_offline_without_override_serves_no_shipped_data(monkeypatch):
    monkeypatch.delenv("CYBERAU_NCSC_SNAPSHOT")
    _all_tools_unavailable()
    assert source.connector().health(live=False, check_schema=True).ok is True


def test_failed_live_fetch_serves_no_shipped_data(monkeypatch):
    _live(monkeypatch)

    def fail(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("network unreachable")

    source._TRANSPORT = httpx.MockTransport(fail)
    _all_tools_unavailable()


def test_override_snapshot_is_marked():
    listed = source.ncscnz_list_alerts()
    assert listed["data"]
    assert any("operator-supplied" in warning for warning in listed["warnings"])
    page = source.ncscnz_get_alert(DATED)
    assert any("operator-supplied" in warning for warning in page["warnings"])
