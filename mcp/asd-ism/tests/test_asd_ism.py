import json
import time
from pathlib import Path

import cyberau_asd_ism.source as source
import httpx
import pytest
from cyberau_asd_ism.source import (
    connector,
    ism_diff,
    ism_get_control,
    ism_list_baseline,
    ism_search,
    schema_drift,
)
from cyberau_common.cache import HttpCache
from cyberau_common.server import build_server

DATA = Path(__file__).resolve().parents[1] / "data"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
RELEASES = "https://api.github.com/repos/AustralianCyberSecurityCentre/ism-oscal/releases"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_ISM_SNAPSHOT", str(DATA))
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    source._SLEEP = lambda _seconds: None
    yield
    source._TRANSPORT = None
    source._SLEEP = time.sleep


def test_control_ids_normalise_and_attribute():
    record = ism_get_control("ISM-1173")
    assert record["data"]["control_id"] == "ism-1173"
    assert record["data"]["release"] == "v2026.09.4"
    assert record["data"]["source_sha256"]
    assert "Multi-factor authentication" in record["data"]["statement"]
    assert "<<untrusted source=ism>>" in record["data"]["statement"]
    assert record["attribution"].startswith("© Commonwealth of Australia 2024")
    same = ism_get_control("1173")
    assert same["data"]["oscal_id"] == "ism-1173"
    missing = ism_get_control("ISM-9999")
    assert missing["data"] is None
    assert missing["warnings"]


def test_search_respects_baseline_and_limit():
    found = ism_search("multi-factor", baseline="E8_ML1", limit=10)
    assert [row["control_id"] for row in found["data"]] == ["ism-1173"]
    broad = ism_search("control", limit=2)
    assert len(broad["data"]) == 2
    assert ism_search("zzzz-not-a-control")["warnings"]
    assert ism_search("x", limit=0)["warnings"]


def test_baseline_and_diff():
    listed = ism_list_baseline("E8_ML1")
    assert listed["data"][0]["control_ids"] == ["ism-1173", "ism-0009"]
    missing = ism_list_baseline("TOP_SECRET", release="v2026.09.4")
    assert missing["warnings"]
    diff = ism_diff("v2026.06.18", "v2026.09.4")
    assert "ism-2124" in diff["data"]["added"]
    assert "ism-0521" in diff["data"]["removed"]
    changed = {row["control_id"] for row in diff["data"]["changed"]}
    assert "ism-0009" in changed
    assert "<<untrusted source=ism>>" in diff["data"]["changed"][0]["to_statement"]


def test_schema_and_live_health(tmp_path, monkeypatch):
    import asyncio

    tools = {tool.name: tool for tool in asyncio.run(build_server(connector()).list_tools())}
    assert tools["ism_get_control"].inputSchema["required"] == ["control_id"]
    assert "ism-" in json.dumps(tools["ism_get_control"].inputSchema)
    assert "E8_ML1" in json.dumps(tools["ism_search"].inputSchema)
    probe = connector().health(live=False, check_schema=True)
    drift = tmp_path / "drift"
    (drift / "v2026.09.4").mkdir(parents=True)
    (drift / "releases.json").write_text(
        json.dumps(
            {"releases": [{"tag_name": "v2026.09.4", "published_at": "2026-09-03T00:00:00Z"}]}
        ),
        encoding="utf-8",
    )
    (drift / "v2026.09.4" / "ISM_catalog.json").write_text(
        (FIXTURES / "drift.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_ISM_SNAPSHOT", str(drift))
    failed = connector().health(live=False, check_schema=True)
    assert probe.ok is True
    assert failed.ok is False
    assert schema_drift({"catalog": {"groups": [{"controls": [{}]}]}})

    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_ISM_SNAPSHOT")
    body = (DATA / "releases.json").read_bytes()
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    key = cache.key("GET", RELEASES, None, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=body, ttl=86400)

    def unavailable(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, content=(FIXTURES / "github_403_rate_limited.json").read_bytes())

    source._TRANSPORT = httpx.MockTransport(unavailable)
    down = connector().health(live=True)
    assert down.ok is False
    assert "GITHUB_TOKEN" in down.detail
    assert "live ok" not in down.detail


def test_redirect_is_refused(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_ISM_SNAPSHOT")

    def redirect(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/stolen"})

    source._TRANSPORT = httpx.MockTransport(redirect)
    refused = ism_get_control("ism-1173", release="v2026.09.4")
    assert refused["warnings"]
    assert "evil.example" in refused["warnings"][0] or "allow" in refused["warnings"][0].lower()


def test_past_release_is_kept():
    older = ism_get_control("ism-0521", release="v2026.06.18")
    assert older["data"]["release"] == "v2026.06.18"
    gone = ism_get_control("ism-0521", release="v2026.09.4")
    assert gone["data"] is None
    assert gone["warnings"]
