import asyncio
import ipaddress
import json
import os
import sqlite3
import tempfile
import time
from pathlib import Path

import cyberau_scamwatch.source as source
import httpx
import jsonschema
from cyberau_common.cache import HttpCache
from cyberau_common.server import build_server
from cyberau_scamwatch.source import (
    HOME,
    TTL,
    connector,
    scamwatch_get_alert,
    scamwatch_list_alerts,
    schema_drift,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SCHEMA = Path(__file__).resolve().parents[1] / "schema"
PAGE = "https://www.scamwatch.gov.au/about-us/news-and-alerts/example-parcel-fee"
ENVELOPE = {
    "type": "object",
    "required": ["source", "retrieved_at", "cache", "data", "untrusted", "attribution"],
    "properties": {
        "source": {"type": "string"},
        "retrieved_at": {"type": "string"},
        "cache": {"enum": ["hit", "miss", "stale", "snapshot"]},
        "data": {},
        "untrusted": {"const": True},
        "attribution": {"type": "string", "minLength": 1},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
}


def setup_function():
    os.environ["CYBERAU_OFFLINE"] = "1"
    os.environ["CYBERAU_SCAMWATCH_SNAPSHOT"] = str(FIXTURES / "homepage_three_alerts.html")
    os.environ.pop("CYBERAU_SCAMWATCH_PAGES", None)
    os.environ["CYBERAU_DATA_DIR"] = tempfile.mkdtemp(prefix="cyberau-scamwatch-")


def test_list_and_get_happy_path(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CYBERAU_SCAMWATCH_PAGES", str(FIXTURES / "pages"))
    listed = scamwatch_list_alerts(limit=10)
    jsonschema.validate({"limit": 10}, _input("scamwatch_list_alerts"))
    jsonschema.validate(listed, ENVELOPE)
    assert listed["cache"] == "snapshot"
    assert listed["source_urls"] == [HOME]
    assert listed["attribution"].startswith("Scamwatch alerts")
    assert listed["data_as_of"] == "2026-09-01"
    assert [row["date"] for row in listed["data"]] == [
        "2026-07-14",
        "2026-08-02",
        "2026-09-01",
    ]
    assert "decoy-before" not in json.dumps(listed["data"])
    assert "example-ignored" not in json.dumps(listed["data"])
    assert "\u202e" not in listed["data"][0]["title"]
    assert "<<untrusted source=scamwatch>>" in listed["data"][0]["title"]
    assert "parcel fee" in listed["data"][0]["title"]
    for row in listed["data"]:
        jsonschema.validate(row, _output("scamwatch_list_alerts"))
    one = scamwatch_list_alerts(limit=1)
    assert len(one["data"]) == 1
    page = scamwatch_get_alert(PAGE)
    jsonschema.validate({"url": PAGE}, _input("scamwatch_get_alert"))
    jsonschema.validate(page, ENVELOPE)
    jsonschema.validate(page["data"], _output("scamwatch_get_alert"))
    assert page["data"]["date"] == "2026-07-14"
    assert "<<untrusted source=scamwatch>>" in page["data"]["body"]
    assert "Skip to content" not in page["data"]["body"]
    assert "Footer noise" not in page["data"]["body"]
    assert "parcel fee" in page["data"]["body"]
    assert page["attribution"]
    with sqlite3.connect(tmp_path / "scamwatch.sqlite") as conn:
        assert conn.execute("select count(*) from alerts").fetchone()[0] == 3


def test_empty_malformed_drift_and_bad_input(monkeypatch):
    monkeypatch.setenv("CYBERAU_SCAMWATCH_SNAPSHOT", str(FIXTURES / "homepage_empty.html"))
    empty = scamwatch_list_alerts()
    assert empty["data"] == []
    assert empty["warnings"]
    assert "blocked" not in empty["warnings"][0]
    assert "no alerts" in empty["warnings"][0]
    monkeypatch.setenv("CYBERAU_SCAMWATCH_SNAPSHOT", str(FIXTURES / "homepage_malformed.html"))
    malformed = scamwatch_list_alerts()
    assert malformed["warnings"]
    assert "schema drift" in malformed["warnings"][0]
    monkeypatch.setenv("CYBERAU_SCAMWATCH_SNAPSHOT", str(FIXTURES / "scamwatch_403.html"))
    denied = scamwatch_list_alerts()
    assert denied["data"] == []
    assert "blocked" in denied["warnings"][0]
    assert "no alerts" not in denied["warnings"][0]
    drift = (FIXTURES / "homepage_drift.html").read_text(encoding="utf-8")
    assert schema_drift(drift)
    monkeypatch.setenv("CYBERAU_SCAMWATCH_SNAPSHOT", str(FIXTURES / "homepage_drift.html"))
    failed = connector().health(live=False, check_schema=True)
    assert failed.ok is False
    monkeypatch.setenv("CYBERAU_SCAMWATCH_SNAPSHOT", str(FIXTURES / "homepage_three_alerts.html"))
    assert connector().health(live=False, check_schema=True).ok is True
    assert scamwatch_list_alerts(limit=0)["warnings"]
    assert scamwatch_get_alert("https://evil.example/phish")["warnings"]
    missing = scamwatch_get_alert("https://www.scamwatch.gov.au/about-us/news-and-alerts/missing")
    assert missing["data"] is None
    assert missing["warnings"]


def test_history_is_kept(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    scamwatch_list_alerts()
    html = (FIXTURES / "homepage_three_alerts.html").read_text(encoding="utf-8")
    changed = html.replace("Example alert: parcel fee", "Example alert: parcel fee updated")
    path = tmp_path / "changed.html"
    path.write_text(changed, encoding="utf-8")
    monkeypatch.setenv("CYBERAU_SCAMWATCH_SNAPSHOT", str(path))
    updated = scamwatch_list_alerts()
    assert "updated" in updated["data"][0]["title"]
    rows = [
        json.loads(line)
        for line in (tmp_path / "scamwatch-alerts.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    titles = [row["title"] for row in rows]
    assert "Example alert: parcel fee" in titles
    assert "Example alert: parcel fee updated" in titles
    with sqlite3.connect(tmp_path / "scamwatch.sqlite") as conn:
        assert conn.execute("select count(*) from alerts").fetchone()[0] == 3


def test_blocked_status_and_retry(tmp_path, monkeypatch):
    _live(monkeypatch, tmp_path)
    body = (FIXTURES / "scamwatch_403.html").read_bytes()

    def denied(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, content=body)

    source._TRANSPORT = httpx.MockTransport(denied)
    try:
        blocked = scamwatch_list_alerts()
    finally:
        source._TRANSPORT = None
    assert blocked["data"] == []
    assert "blocked" in blocked["warnings"][0]
    assert "403" in blocked["warnings"][0]
    assert "no alerts" not in blocked["warnings"][0]

    def unauthorised(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, content=body)

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "unauthorised"))
    source._TRANSPORT = httpx.MockTransport(unauthorised)
    try:
        denied_auth = scamwatch_list_alerts()
    finally:
        source._TRANSPORT = None
    assert "blocked" in denied_auth["warnings"][0]
    assert "401" in denied_auth["warnings"][0]

    calls = {"n": 0}
    page = (FIXTURES / "homepage_three_alerts.html").read_bytes()

    def retry(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "0"})
        return httpx.Response(200, content=page)

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "retry"))
    source._TRANSPORT = httpx.MockTransport(retry)
    try:
        recovered = scamwatch_list_alerts()
    finally:
        source._TRANSPORT = None
    assert calls["n"] >= 2
    assert recovered["data"][0]["date"] == "2026-07-14"


def test_timeout_falls_back_to_cache_and_redirect_is_refused(tmp_path, monkeypatch):
    _live(monkeypatch, tmp_path)
    page = (FIXTURES / "homepage_three_alerts.html").read_bytes()
    _seed(tmp_path, page, age=7 * 3600)

    def timed_out(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    source._TRANSPORT = httpx.MockTransport(timed_out)
    try:
        stale = scamwatch_list_alerts()
    finally:
        source._TRANSPORT = None
    assert stale["cache"] == "stale"
    assert stale["data"][0]["date"] == "2026-07-14"
    assert stale["warnings"]

    def redirect(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/stolen"})

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "redirect"))
    source._TRANSPORT = httpx.MockTransport(redirect)
    try:
        refused = scamwatch_list_alerts()
    finally:
        source._TRANSPORT = None
    assert refused["warnings"]
    assert "evil.example" in refused["warnings"][0]

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "empty-timeout"))
    source._TRANSPORT = httpx.MockTransport(timed_out)
    try:
        missing = scamwatch_list_alerts()
    finally:
        source._TRANSPORT = None
    assert missing["data"] == []
    assert missing["warnings"]


def test_repeat_call_after_403_still_says_blocked(tmp_path, monkeypatch):
    _live(monkeypatch, tmp_path)
    body = (FIXTURES / "scamwatch_403.html").read_bytes()
    source._TRANSPORT = httpx.MockTransport(lambda _request: httpx.Response(403, content=body))
    try:
        results = [scamwatch_list_alerts(), scamwatch_list_alerts()]
        alert = scamwatch_get_alert(PAGE)
        again = scamwatch_get_alert(PAGE)
        probes = [connector().health(live=True), connector().health(live=True)]
    finally:
        source._TRANSPORT = None
    for result in results:
        assert result["data"] == []
        assert "blocked" in result["warnings"][0]
    assert alert["data"] is None
    assert "blocked" in alert["warnings"][0]
    assert "blocked" in again["warnings"][0]
    assert all(not probe.ok and "blocked" in probe.detail for probe in probes)


def test_alert_page_read_keeps_homepage_fields(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CYBERAU_SCAMWATCH_PAGES", str(FIXTURES / "pages"))
    scamwatch_list_alerts()
    scamwatch_get_alert(PAGE + "#top")
    scamwatch_list_alerts()
    scamwatch_get_alert(HOME)
    with sqlite3.connect(tmp_path / "scamwatch.sqlite") as conn:
        assert conn.execute("select count(*) from alerts").fetchone()[0] == 3
        summary, body = conn.execute(
            "select summary, body from alerts where url = ?", (PAGE,)
        ).fetchone()
    assert summary
    assert "parcel fee" in body
    rows = (tmp_path / "scamwatch-alerts.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(rows) == 4


def test_403_with_cache_is_not_an_empty_list(tmp_path, monkeypatch):
    _live(monkeypatch, tmp_path)
    page = (FIXTURES / "homepage_three_alerts.html").read_bytes()
    _seed(tmp_path, page, age=7 * 3600)

    def denied(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, content=(FIXTURES / "scamwatch_403.html").read_bytes())

    source._TRANSPORT = httpx.MockTransport(denied)
    try:
        blocked = scamwatch_list_alerts()
    finally:
        source._TRANSPORT = None
    assert blocked["cache"] == "stale"
    assert blocked["data"]
    assert "blocked" in blocked["warnings"][0]
    assert "403" in blocked["warnings"][0]


def test_advertised_schema_and_live_health(tmp_path, monkeypatch):
    tools = {tool.name: tool for tool in asyncio.run(build_server(connector()).list_tools())}
    assert tools["scamwatch_list_alerts"].inputSchema["properties"]["limit"]["maximum"] == 50
    url_schema = tools["scamwatch_get_alert"].inputSchema["properties"]["url"]
    assert tools["scamwatch_get_alert"].inputSchema["required"] == ["url"]
    assert url_schema["pattern"] == r"^https://www\.scamwatch\.gov\.au/"
    _live(monkeypatch, tmp_path)
    body = (FIXTURES / "homepage_three_alerts.html").read_bytes()

    def ok(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(ok)
    try:
        probe = connector().health(live=True)
    finally:
        source._TRANSPORT = None
    assert probe.ok is True
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "down"))

    def down(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, content=(FIXTURES / "scamwatch_403.html").read_bytes())

    source._TRANSPORT = httpx.MockTransport(down)
    try:
        failed = connector().health(live=True)
    finally:
        source._TRANSPORT = None
    assert failed.ok is False
    assert "blocked" in failed.detail


def test_offline_without_snapshot_uses_cache_or_warns(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_SCAMWATCH_SNAPSHOT", raising=False)
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "none"))
    monkeypatch.setattr(source, "_shipped_home", lambda: "")
    missing = scamwatch_list_alerts()
    assert missing["cache"] == "snapshot"
    assert missing["warnings"]
    assert missing["data"] == []
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    html = (FIXTURES / "homepage_three_alerts.html").read_text(encoding="utf-8")
    cached_html = html.replace("Example alert: parcel fee", "Example alert: cached only")
    _seed(tmp_path, cached_html.encode(), age=0)
    cached = scamwatch_list_alerts()
    assert cached["cache"] in {"hit", "stale"}
    assert "cached only" in cached["data"][0]["title"]


def test_cassettes_replay():
    import vcr
    from vcr.serialize import deserialize
    from vcr.serializers import yamlserializer

    player = vcr.VCR(record_mode="none")
    uris = {
        "scamwatch_list_alerts": HOME,
        "scamwatch_get_alert": PAGE,
    }
    for name, uri in uris.items():
        path = FIXTURES / f"{name}.yaml"
        _requests, responses = deserialize(path.read_text(encoding="utf-8"), yamlserializer)
        assert responses[0]["status"]["code"] == 200
        with player.use_cassette(str(path)):
            played = httpx.get(uri)
        assert played.status_code == 200
        assert b"Example alert: parcel fee" in played.content


def _live(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.delenv("CYBERAU_SCAMWATCH_SNAPSHOT", raising=False)
    monkeypatch.delenv("CYBERAU_SCAMWATCH_PAGES", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(source, "_SLEEP", lambda _seconds: None)
    monkeypatch.setattr(
        "cyberau_common.egress._resolve",
        lambda _host: [ipaddress.ip_address("1.1.1.1")],
    )


def _seed(tmp_path: Path, body: bytes, *, age: int) -> None:
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    key = cache.key("GET", HOME, None, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=body, ttl=TTL)
    if age:
        with sqlite3.connect(tmp_path / "http_cache.sqlite") as conn:
            conn.execute("UPDATE http_cache SET fetched_at = ?", (time.time() - age,))


def _input(name: str) -> dict:
    return json.loads((SCHEMA / f"{name}.input.json").read_text(encoding="utf-8"))


def _output(name: str) -> dict:
    return json.loads((SCHEMA / f"{name}.response.json").read_text(encoding="utf-8"))
