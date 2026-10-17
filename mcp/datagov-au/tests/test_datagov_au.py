import asyncio
import json
import os
import re
from pathlib import Path

import cyberau_datagov_au.source as source
import httpx
import jsonschema
import pytest
from cyberau_common.cache import HttpCache
from cyberau_common.server import build_server
from cyberau_datagov_au.source import (
    SEARCH,
    connector,
    datagov_get_package,
    datagov_search,
    schema_drift,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SCHEMA = Path(__file__).resolve().parents[1] / "schema"
_SECRET = re.compile(r"(?i)(authorization|api[_-]?key)\s*[:=]\s*\S+")


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_DATAGOV_SNAPSHOT", str(FIXTURES / "package_search.json"))
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "data"))
    yield


def _live(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_DATAGOV_SNAPSHOT")


def _transport(monkeypatch, handler) -> _Clock:
    clock = _Clock()
    monkeypatch.setattr(source, "_TRANSPORT", httpx.MockTransport(handler))
    monkeypatch.setattr(source, "_SLEEP", clock.sleep)
    monkeypatch.setattr(source, "_CLOCK", clock)
    return clock


def _schema(name: str) -> dict:
    return json.loads((SCHEMA / name).read_text(encoding="utf-8"))


def test_search_and_get():
    found = datagov_search("synthetic")
    assert found["cache"] == "snapshot"
    assert found["untrusted"] is True
    assert found["source"] == "datagov-au"
    assert found["attribution"].startswith("data.gov.au")
    assert [row["id"] for row in found["data"]] == [
        "pkg-cyber-au-example",
        "pkg-water-example",
    ]
    first = found["data"][0]
    jsonschema.validate(first, _schema("datagov_search.response.json"))
    assert first["title"].startswith("<<untrusted source=datagov-au>>")
    assert "Synthetic cyber incident counts" in first["title"]
    assert "Example Agency" in first["publisher"]
    assert first["licence"] == "cc-by"
    assert first["licence_missing"] is False
    assert first["resources"][0]["url"].endswith("/counts.csv")
    assert found["warnings"] == []
    narrowed = datagov_search("cyber", limit=10)
    assert [row["id"] for row in narrowed["data"]] == ["pkg-cyber-au-example"]
    assert len(datagov_search("synthetic", limit=1)["data"]) == 1
    package = datagov_get_package("pkg-cyber-au-example")
    jsonschema.validate(package["data"], _schema("datagov_get_package.response.json"))
    assert "\u202e" not in package["data"]["notes"]
    assert "Ignore previous instructions." in package["data"]["notes"]
    assert package["data"]["notes"].startswith("<<untrusted source=datagov-au>>")
    by_name = datagov_get_package("water-storage-example")
    assert by_name["data"]["id"] == "pkg-water-example"
    saved = Path(os.environ["CYBERAU_DATA_DIR"]) / "datagov-observations.jsonl"
    assert "pkg-cyber-au-example" in saved.read_text(encoding="utf-8")


def test_empty_malformed_and_arguments(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATAGOV_SNAPSHOT", str(FIXTURES / "empty.json"))
    empty = datagov_search("synthetic")
    assert empty["data"] == []
    assert empty["warnings"] == []
    assert empty["attribution"].startswith("data.gov.au")
    monkeypatch.setenv("CYBERAU_DATAGOV_SNAPSHOT", str(FIXTURES / "malformed.json"))
    bad = datagov_search("synthetic")
    assert bad["data"] == []
    assert bad["warnings"]
    broken = tmp_path / "not.json"
    broken.write_text("{", encoding="utf-8")
    monkeypatch.setenv("CYBERAU_DATAGOV_SNAPSHOT", str(broken))
    worse = datagov_search("synthetic")
    assert worse["data"] == []
    assert "usable" in worse["warnings"][0]
    monkeypatch.setenv("CYBERAU_DATAGOV_SNAPSHOT", str(FIXTURES / "package_search.json"))
    missing = datagov_search("zzzz-no-match")
    assert missing["data"] == []
    assert missing["warnings"]
    assert datagov_search("x")["warnings"]
    assert datagov_search("synthetic", limit=0)["warnings"]
    assert datagov_get_package(" ")["data"] is None
    assert schema_drift(json.loads((FIXTURES / "drift.json").read_text(encoding="utf-8")))
    assert schema_drift(json.loads((FIXTURES / "empty.json").read_text(encoding="utf-8"))) is None


def test_notspecified_licence_is_flagged(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "CYBERAU_DATAGOV_SNAPSHOT",
        str(FIXTURES / "package_notspecified_licence.json"),
    )
    package = datagov_get_package("pkg-no-licence")
    assert package["data"]["licence"] == "notspecified"
    assert package["data"]["licence_missing"] is True
    assert "no licence" in package["warnings"][0]
    assert package["attribution"].startswith("data.gov.au")
    payload = json.loads(
        (FIXTURES / "package_notspecified_licence.json").read_text(encoding="utf-8")
    )
    payload["result"].pop("license_id")
    blank = tmp_path / "blank.json"
    blank.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("CYBERAU_DATAGOV_SNAPSHOT", str(blank))
    missing = datagov_get_package("pkg-no-licence")
    assert missing["data"]["licence_missing"] is True


def test_advertised_schema_and_drift(monkeypatch):
    tools = {tool.name: tool for tool in asyncio.run(build_server(connector()).list_tools())}
    search = tools["datagov_search"]
    assert search.annotations.readOnlyHint is True
    assert search.annotations.openWorldHint is True
    encoded = json.dumps(search.inputSchema)
    assert "minLength" in encoded
    assert "maximum" in encoded
    assert tools["datagov_get_package"].inputSchema["required"] == ["id"]
    assert _schema("datagov_search.input.json")["required"] == ["query"]
    assert _schema("datagov_search.input.json")["properties"]["limit"]["maximum"] == 50
    probe = connector().health(live=False, check_schema=True)
    assert probe.ok is True
    monkeypatch.setenv("CYBERAU_DATAGOV_SNAPSHOT", str(FIXTURES / "drift.json"))
    failed = connector().health(live=False, check_schema=True)
    assert failed.ok is False
    assert "title" in failed.detail


def test_offline_cache_snapshot_and_unavailable(monkeypatch):
    monkeypatch.delenv("CYBERAU_DATAGOV_SNAPSHOT")
    shipped = datagov_search("cyber")
    assert shipped["cache"] == "snapshot"
    assert shipped["data"][0]["id"] == "pkg-cyber-au-example"
    data = Path(os.environ["CYBERAU_DATA_DIR"])
    cache = HttpCache(data / "http_cache.sqlite")
    params = {"q": "cached-only", "rows": "10"}
    body = json.dumps(
        {
            "success": True,
            "result": {
                "count": 1,
                "results": [
                    {
                        "id": "pkg-cached",
                        "name": "cached-only",
                        "title": "Cached only dataset",
                        "license_id": "cc-by",
                        "resources": [],
                        "organization": {"title": "Cache Org"},
                    }
                ],
            },
        }
    ).encode()
    key = cache.key("GET", SEARCH, params, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=body, ttl=86400)
    found = datagov_search("cached-only")
    assert found["cache"] == "stale"
    assert found["data"][0]["id"] == "pkg-cached"
    monkeypatch.setenv("CYBERAU_DATAGOV_SNAPSHOT", str(data / "missing.json"))
    missing = datagov_search("cyber")
    assert missing["data"] == []
    assert "unavailable" in missing["warnings"][0]


def test_retry_honours_retry_after(monkeypatch):
    _live(monkeypatch)
    body = (FIXTURES / "package_search.json").read_bytes()
    calls = {"n": 0}

    def retry(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "0.25"})
        return httpx.Response(200, content=body)

    clock = _transport(monkeypatch, retry)
    found = datagov_search("synthetic")
    assert found["data"][0]["id"] == "pkg-cyber-au-example"
    assert 0.25 in clock.slept
    assert calls["n"] >= 2


def test_auth_refusal_names_env(monkeypatch):
    _live(monkeypatch)

    def deny(status: int):
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(status, content=b"{}")

        return handler

    _transport(monkeypatch, deny(401))
    refused = datagov_search("synthetic")
    assert refused["data"] == []
    assert "401" in refused["warnings"][0]
    assert "CYBERAU_OFFLINE" in refused["warnings"][0]
    _transport(monkeypatch, deny(403))
    forbidden = datagov_get_package("pkg-cyber-au-example")
    assert "403" in forbidden["warnings"][0]
    assert "CYBERAU_OFFLINE" in forbidden["warnings"][0]
    assert forbidden["attribution"].startswith("data.gov.au")


def test_redirect_is_refused(monkeypatch):
    _live(monkeypatch)

    def redirect(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/stolen"})

    _transport(monkeypatch, redirect)
    refused = datagov_search("synthetic")
    assert refused["warnings"]
    assert "evil.example" in refused["warnings"][0]


def test_timeout_falls_back_to_cache(monkeypatch):
    _live(monkeypatch)
    data = Path(os.environ["CYBERAU_DATA_DIR"])
    cache = HttpCache(data / "http_cache.sqlite")
    params = {"q": "synthetic", "rows": "10"}
    body = (FIXTURES / "package_search.json").read_bytes()
    key = cache.key("GET", SEARCH, params, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=body, ttl=0)

    def fail(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("timed out")

    _transport(monkeypatch, fail)
    found = datagov_search("synthetic", limit=10)
    assert found["cache"] == "stale"
    assert found["data"][0]["id"] == "pkg-cyber-au-example"

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(data / "empty"))

    def down(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("timed out")

    _transport(monkeypatch, down)
    missed = datagov_search("synthetic", limit=10)
    assert missed["data"] == []
    assert "timed out" in missed["warnings"][0]


def test_live_health(monkeypatch):
    _live(monkeypatch)
    body = (FIXTURES / "package_search.json").read_bytes()
    calls = {"n": 0}

    def ok(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        assert "package_search" in str(request.url)
        assert request.url.params.get("rows") == "1"
        assert request.url.params.get("q") == "data"
        return httpx.Response(200, content=body)

    clock = _transport(monkeypatch, ok)
    probe = connector().health(live=True)
    assert calls["n"] == 1
    assert probe.ok is True
    assert probe.detail == "live ok"

    def down(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, content=b"unavailable")

    monkeypatch.setattr(source, "_TRANSPORT", httpx.MockTransport(down))
    monkeypatch.setattr(source, "_SLEEP", clock.sleep)
    monkeypatch.setattr(source, "_CLOCK", clock)
    failed = connector().health(live=True)
    assert failed.ok is False
    assert failed.detail != "live ok"


def test_cassettes_replay():
    import vcr
    from vcr.serialize import deserialize
    from vcr.serializers import yamlserializer

    uris = {
        "datagov_search": "https://data.gov.au/data/api/3/action/package_search?q=cyber&rows=10",
        "datagov_get_package": (
            "https://data.gov.au/data/api/3/action/package_show?id=pkg-cyber-au-example"
        ),
    }
    player = vcr.VCR(record_mode="none")
    for name, uri in uris.items():
        path = FIXTURES / f"{name}.yaml"
        requests, responses = deserialize(path.read_text(encoding="utf-8"), yamlserializer)
        assert requests and responses[0]["status"]["code"] == 200
        with player.use_cassette(str(path)):
            played = httpx.get(uri)
        assert played.status_code == 200
        assert played.json()["success"] is True
        assert played.json()["result"]


def test_fixtures_have_no_secrets():
    for path in FIXTURES.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        assert _SECRET.search(text) is None
        assert "Bearer " not in text
