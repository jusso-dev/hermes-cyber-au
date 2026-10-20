import asyncio
import json
import sqlite3
import time
from pathlib import Path

import cyberau_openphish.source as source
import httpx
import jsonschema
import pytest
from cyberau_common.cache import HttpCache
from cyberau_common.ratelimit import RateLimited
from cyberau_common.server import build_server
from cyberau_openphish.source import (
    FEED_URL,
    connector,
    phish_check_url,
    schema_drift,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ROOT = Path(__file__).resolve().parents[1]
QUERY = "https://phish.example/login"
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
        "data": {"type": "array"},
    },
}


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_OPENPHISH_SNAPSHOT", str(FIXTURES / "feed_three_lines.txt"))
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    source._SLEEP = lambda _seconds: None
    yield
    source._TRANSPORT = None
    source._SLEEP = time.sleep


def _row(payload, name):
    return next(item for item in payload["data"] if item["source"] == name)


def _schemas():
    schema_dir = ROOT / "schema"
    return (
        json.loads((schema_dir / "phish_check_url.input.json").read_text(encoding="utf-8")),
        json.loads((schema_dir / "phish_check_url.response.json").read_text(encoding="utf-8")),
    )


def _live(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.delenv("CYBERAU_OPENPHISH_SNAPSHOT", raising=False)


def test_happy_path_matches_schemas_and_wraps_text():
    found = phish_check_url(QUERY)
    input_schema, response_schema = _schemas()
    jsonschema.validate({"url": QUERY}, input_schema)
    jsonschema.validate(found, ENVELOPE)
    assert found["cache"] == "snapshot"
    assert found["attribution"].startswith("OpenPhish community feed")
    assert any("snapshot" in item and "not live" in item for item in found["warnings"])
    row = _row(found, "openphish")
    jsonschema.validate(row, response_schema)
    assert row["listed"] is True
    assert "<<untrusted source=openphish>>" in row["url"]
    assert "<<untrusted source=openphish>>" in row["detail"]
    assert "phish.example/login" in row["detail"]
    assert _row(found, "phishtank")["listed"] is False
    assert _row(found, "urlhaus")["listed"] is False
    slash = phish_check_url(QUERY + "/")
    assert _row(slash, "openphish")["listed"] is True


def test_empty_result_and_empty_feed(monkeypatch):
    missing = phish_check_url("https://absent.example/nope")
    assert all("snapshot" in item for item in missing["warnings"])
    assert all(row["listed"] is False for row in missing["data"])
    assert "snapshot copy" in _row(missing, "openphish")["detail"]
    monkeypatch.setenv("CYBERAU_OPENPHISH_SNAPSHOT", str(FIXTURES / "feed_empty.txt"))
    empty = phish_check_url(QUERY)
    assert empty["data"]
    assert _row(empty, "openphish")["listed"] is False
    assert any("empty" in item for item in empty["warnings"])


def test_malformed_payload_warns(monkeypatch):
    monkeypatch.setenv("CYBERAU_OPENPHISH_SNAPSHOT", str(FIXTURES / "feed_malformed.txt"))
    warned = phish_check_url(QUERY)
    assert warned["warnings"]
    assert "url" in warned["warnings"][0]
    assert "is unavailable" in warned["warnings"][0]
    assert warned["data"] == []
    assert schema_drift((FIXTURES / "feed_drift.txt").read_text(encoding="utf-8"))


def test_schema_drift_fails_health():
    assert connector().health(live=False, check_schema=True).ok is True
    assert schema_drift("") is None


def test_schema_drift_fixture_fails_probe(monkeypatch):
    monkeypatch.setenv("CYBERAU_OPENPHISH_SNAPSHOT", str(FIXTURES / "feed_drift.txt"))
    probe = connector().health(live=False, check_schema=True)
    assert probe.ok is False
    assert "url" in probe.detail
    from cyberau_common.cli import main

    assert main(["health", "openphish", "--schema-drift"]) == 1


def test_auth_errors_name_the_env_var(tmp_path, monkeypatch):
    _live(monkeypatch)

    def denied(status):
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(status, content=b"no")

        return handler

    for status in (401, 403):
        directory = tmp_path / str(status)
        directory.mkdir()
        monkeypatch.setenv("CYBERAU_DATA_DIR", str(directory))
        source._TRANSPORT = httpx.MockTransport(denied(status))
        warned = phish_check_url(QUERY)
        assert str(status) in warned["warnings"][0]
        assert "env var" in warned["warnings"][0]
        assert "is unavailable" in warned["warnings"][0]
        assert warned["data"] == []


def test_retry_after_then_success(monkeypatch):
    _live(monkeypatch)
    slept = []
    source._SLEEP = slept.append
    calls = {"n": 0}
    body = (FIXTURES / "feed_three_lines.txt").read_bytes()

    def retry(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "0"})
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(retry)
    found = phish_check_url(QUERY)
    assert _row(found, "openphish")["listed"] is True
    assert calls["n"] >= 2
    assert 0 in slept or 0.0 in slept


def test_timeout_falls_back_to_cache(tmp_path, monkeypatch):
    _live(monkeypatch)
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    body = (FIXTURES / "feed_three_lines.txt").read_bytes()
    key = cache.key("GET", FEED_URL, None, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=body, ttl=0)

    def timeout(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    source._TRANSPORT = httpx.MockTransport(timeout)
    found = phish_check_url(QUERY)
    assert found["cache"] == "stale"
    assert _row(found, "openphish")["listed"] is True
    assert found["warnings"] == []


def test_empty_feed_does_not_wipe_cache(tmp_path, monkeypatch):
    _live(monkeypatch)
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    body = (FIXTURES / "feed_three_lines.txt").read_bytes()
    key = cache.key("GET", FEED_URL, None, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=body, ttl=0)

    def empty(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"\n")

    source._TRANSPORT = httpx.MockTransport(empty)
    found = phish_check_url(QUERY)
    assert found["cache"] == "stale"
    assert _row(found, "openphish")["listed"] is True
    assert any("empty" in item for item in found["warnings"])
    kept = cache.get(key)
    assert kept is not None
    assert b"phish.example/login" in kept.body


def test_redirect_off_allowlist_is_refused(monkeypatch):
    _live(monkeypatch)

    def redirect(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/feed.txt"})

    source._TRANSPORT = httpx.MockTransport(redirect)
    refused = phish_check_url(QUERY)
    assert refused["warnings"]
    assert "evil.example" in refused["warnings"][0]
    assert refused["data"] == []


def test_github_path_outside_the_feed_is_refused(monkeypatch):
    _live(monkeypatch)

    def redirect(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"location": "https://raw.githubusercontent.com/other/repo/feed.txt"},
        )

    source._TRANSPORT = httpx.MockTransport(redirect)
    refused = phish_check_url(QUERY)
    assert refused["warnings"]
    assert "is unavailable" in refused["warnings"][0]
    assert refused["data"] == []


def test_follows_the_public_feed_redirect(monkeypatch):
    _live(monkeypatch)
    body = (FIXTURES / "feed_three_lines.txt").read_bytes()
    seen = []

    def redirect(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.host == "openphish.com":
            return httpx.Response(
                302,
                headers={
                    "location": (
                        "https://raw.githubusercontent.com"
                        "/openphish/public_feed/refs/heads/main/feed.txt"
                    )
                },
            )
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(redirect)
    found = phish_check_url(QUERY)
    assert _row(found, "openphish")["listed"] is True
    assert seen
    assert all("phish.example" not in item for item in seen)
    assert all(item.startswith("https://openphish.com/") or "public_feed" in item for item in seen)


def test_sibling_caches_and_history(tmp_path, monkeypatch):
    phish_dir = tmp_path / "phishtank"
    phish_dir.mkdir()
    (phish_dir / "online-valid.json").write_text(
        json.dumps([{"url": "https://bank.example/verify", "phish_id": "1"}]),
        encoding="utf-8",
    )
    haus = tmp_path / "urlhaus"
    haus.mkdir()
    (haus / "recent.json").write_text(
        json.dumps({"urls": [{"url": "https://files.example/invoice"}]}),
        encoding="utf-8",
    )
    found = phish_check_url("https://bank.example/verify")
    assert _row(found, "openphish")["listed"] is False
    assert _row(found, "phishtank")["listed"] is True
    assert "<<untrusted source=phishtank>>" in _row(found, "phishtank")["detail"]
    assert _row(found, "urlhaus")["listed"] is False
    _live(monkeypatch)
    feed = {"body": b"https://phish.example/login\n"}
    source._TRANSPORT = httpx.MockTransport(
        lambda _request: httpx.Response(200, content=feed["body"])
    )
    phish_check_url("https://phish.example/login")
    for name in ("http_cache.sqlite", "rate_limit.sqlite"):
        (tmp_path / name).unlink()
    feed["body"] = b"https://other.example/new\n"
    phish_check_url("https://other.example/new")
    kept = {
        row[0]
        for row in sqlite3.connect(tmp_path / "openphish.sqlite").execute(
            "SELECT url FROM indicators WHERE source = 'openphish'"
        )
    }
    assert "https://phish.example/login" in kept
    assert "https://other.example/new" in kept


def test_snapshot_is_never_written_to_the_history_store(tmp_path):
    found = phish_check_url(QUERY)
    assert found["cache"] == "snapshot"
    assert _row(found, "openphish")["listed"] is True
    assert not (tmp_path / "openphish.sqlite").exists()


FIXTURE_VALUES = ("phish.example", "/reset", "/pay")


def _assert_unavailable(found):
    jsonschema.validate(found, ENVELOPE)
    assert found["data"] == []
    assert any("OpenPhish feed is unavailable" in item for item in found["warnings"])
    text = json.dumps(found["data"])
    assert all(value not in text for value in FIXTURE_VALUES)
    assert not any("snapshot dated" in item or "synthetic" in item for item in found["warnings"])


def test_offline_without_override_serves_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_OPENPHISH_SNAPSHOT")
    found = phish_check_url(QUERY)
    _assert_unavailable(found)
    assert "offline" in found["warnings"][0]
    assert not (tmp_path / "openphish.sqlite").exists()
    assert not (ROOT / "data").exists()


def test_failed_live_without_override_serves_nothing(tmp_path, monkeypatch):
    _live(monkeypatch)

    def down(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("network down")

    source._TRANSPORT = httpx.MockTransport(down)
    found = phish_check_url(QUERY)
    _assert_unavailable(found)
    assert not (tmp_path / "openphish.sqlite").exists()


def test_offline_schema_check_without_local_copy(monkeypatch):
    monkeypatch.delenv("CYBERAU_OPENPHISH_SNAPSHOT")
    probe = connector().health(live=False, check_schema=True)
    assert probe.ok is True
    assert "no local copy" in probe.detail


def test_offline_cache_beats_snapshot_and_missing_snapshot_warns(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_OPENPHISH_SNAPSHOT")
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    body = b"https://cached.example/only\n"
    key = cache.key("GET", FEED_URL, None, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=body, ttl=10)
    found = phish_check_url("https://cached.example/only")
    assert found["cache"] == "stale"
    assert _row(found, "openphish")["listed"] is True
    monkeypatch.setenv("CYBERAU_OPENPHISH_SNAPSHOT", str(tmp_path / "missing.txt"))
    missing = phish_check_url(QUERY)
    assert missing["warnings"]
    assert "is unavailable" in missing["warnings"][0]
    assert missing["data"] == []
    probe = connector().health(live=False, check_schema=True)
    assert probe.ok is False
    assert "missing" in probe.detail


def test_hourly_ceiling_does_not_call_upstream(monkeypatch):
    _live(monkeypatch)
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, content=b"https://phish.example/login\n")

    source._TRANSPORT = httpx.MockTransport(handler)
    source._limit_feed()
    with pytest.raises(RateLimited):
        source._limit_feed()
    warned = phish_check_url(QUERY)
    assert calls["n"] == 0
    assert "hourly" in warned["warnings"][0]
    assert "is unavailable" in warned["warnings"][0]
    assert warned["data"] == []


def test_live_health_hits_upstream_and_checks_response_schema(tmp_path, monkeypatch):
    _live(monkeypatch)
    body = (FIXTURES / "feed_three_lines.txt").read_bytes()
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    key = cache.key("GET", FEED_URL, None, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=body, ttl=86400)
    calls = {"n": 0}

    def ok(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(ok)
    probe = connector().health(live=True)
    assert calls["n"] == 1
    assert probe.ok is True
    for name in ("rate_limit.sqlite", "rate_limit.sqlite-wal", "rate_limit.sqlite-shm"):
        leftover = tmp_path / name
        if leftover.exists():
            leftover.unlink()

    def down(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, content=b"down")

    source._TRANSPORT = httpx.MockTransport(down)
    failed = connector().health(live=True)
    assert failed.ok is False
    assert "503" in failed.detail


def test_invalid_url_does_not_fetch():
    refused = phish_check_url("example")
    assert refused["cache"] == "snapshot"
    assert refused["data"] == []
    assert refused["warnings"]
    assert phish_check_url("https://user:example@phish.example/login")["warnings"]


def test_advertised_tool_is_read_only():
    tools = asyncio.run(build_server(connector()).list_tools())
    assert tools[0].name == "phish_check_url"
    assert tools[0].annotations.read_only_hint is True
    assert tools[0].annotations.open_world_hint is True
    assert connector().server_name == "phish"
    assert len("mcp__phish__phish_check_url") == 27


def test_cassette_replays_without_auth_headers():
    import vcr
    from vcr.serialize import deserialize
    from vcr.serializers import yamlserializer

    path = FIXTURES / "phish_check_url.yaml"
    text = path.read_text(encoding="utf-8")
    assert "authorization:" not in text.lower()
    requests, responses = deserialize(text, yamlserializer)
    assert requests and responses[0]["status"]["code"] == 200
    player = vcr.VCR(record_mode="none")
    with player.use_cassette(str(path)):
        played = httpx.get(FEED_URL)
    assert played.status_code == 200
    assert "phish.example/login" in played.text


def test_sibling_renamed_field_warns(tmp_path, monkeypatch):
    path = tmp_path / "phishtank"
    path.mkdir()
    (path / "online-valid.json").write_text(
        json.dumps([{"phish_url": "https://bank.example/verify"}]),
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_PHISHTANK_CACHE", str(path / "online-valid.json"))
    found = phish_check_url(QUERY)
    assert any("PhishTank" in item and "url" in item for item in found["warnings"])
    assert _row(found, "phishtank")["listed"] is False


def test_live_health_not_ok_on_cached_copy_when_rate_limited(tmp_path, monkeypatch):
    _live(monkeypatch)
    body = (FIXTURES / "feed_three_lines.txt").read_bytes()
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    key = cache.key("GET", FEED_URL, None, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=body, ttl=0)
    calls = {"n": 0}

    def ok(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(ok)
    source._limit_feed()
    probe = connector().health(live=True)
    assert calls["n"] == 0
    assert probe.ok is False
    assert "hourly" in probe.detail


def test_live_health_not_ok_on_timeout_with_cached_copy(tmp_path, monkeypatch):
    _live(monkeypatch)
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    key = cache.key("GET", FEED_URL, None, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=b"https://phish.example/login\n", ttl=86400)

    def timeout(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    source._TRANSPORT = httpx.MockTransport(timeout)
    assert connector().health(live=True).ok is False


def test_live_health_not_ok_on_non_feed_body(tmp_path, monkeypatch):
    _live(monkeypatch)
    source._TRANSPORT = httpx.MockTransport(
        lambda _request: httpx.Response(200, content=b"<html>not a feed</html>")
    )
    assert connector().health(live=True).ok is False


def test_unparseable_urls_do_not_raise(monkeypatch):
    for query in ("https://a.example:99999/", "http://[::1/x", "https://a.example:abc/"):
        refused = phish_check_url(query)
        assert refused["data"] == []
        assert refused["warnings"]
    assert schema_drift("https://a.example:abc/x")
    assert schema_drift("http://[::1/x")
    monkeypatch.setenv("CYBERAU_OPENPHISH_SNAPSHOT", str(FIXTURES / "feed_badport.txt"))
    warned = phish_check_url(QUERY)
    assert warned["warnings"]
    assert warned["data"] == []


def test_encoded_dot_segments_on_github_are_refused(monkeypatch):
    _live(monkeypatch)
    hostile = (
        "https://raw.githubusercontent.com/openphish/public_feed/%2e%2e/%2e%2e/evil/repo/feed.txt"
    )
    seen = []

    def redirect(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.host == "openphish.com":
            return httpx.Response(302, headers={"location": hostile})
        return httpx.Response(200, content=b"https://phish.example/login\n")

    source._TRANSPORT = httpx.MockTransport(redirect)
    refused = phish_check_url(QUERY)
    assert seen == [FEED_URL]
    assert refused["warnings"]
    assert "is unavailable" in refused["warnings"][0]
    assert refused["data"] == []


def test_sibling_cache_still_answers_when_feed_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_OPENPHISH_SNAPSHOT")
    phish_dir = tmp_path / "phishtank"
    phish_dir.mkdir()
    (phish_dir / "online-valid.json").write_text(
        json.dumps([{"url": "https://bank.example/verify"}]), encoding="utf-8"
    )
    found = phish_check_url("https://bank.example/verify")
    assert "is unavailable" in found["warnings"][0]
    assert all(row["source"] != "openphish" for row in found["data"])
    assert _row(found, "phishtank")["listed"] is True
