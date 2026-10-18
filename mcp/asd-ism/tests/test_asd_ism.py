import json
import time
from datetime import date, timedelta
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

FIXTURES = Path(__file__).resolve().parent / "fixtures"
# Small excerpts of real releases, laid out like the shipped data directory.
DATA = FIXTURES
SHIPPED = Path(__file__).resolve().parents[1] / "data"
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


def _shipped_retrieved_on():
    return date.fromisoformat(json.loads((SHIPPED / "releases.json").read_text())["retrieved_on"])


def test_shipped_catalogue_is_full_and_labelled(monkeypatch):
    monkeypatch.delenv("CYBERAU_ISM_SNAPSHOT")
    monkeypatch.setattr(source, "_TODAY", _shipped_retrieved_on)
    record = ism_get_control("ism-1546")
    assert record["data"]["control_id"] == "ism-1546"
    assert record["cache"] == "snapshot"
    assert record["data_as_of"] == "v2026.09.4"
    assert any("served the shipped ISM" in warning for warning in record["warnings"])
    listed = ism_list_baseline("TOP_SECRET")
    assert len(listed["data"][0]["control_ids"]) > 100


def test_expired_shipped_release_list_is_refused(monkeypatch):
    monkeypatch.delenv("CYBERAU_ISM_SNAPSHOT")
    expired = _shipped_retrieved_on() + timedelta(days=source.SNAPSHOT_MAX_AGE_DAYS + 1)
    monkeypatch.setattr(source, "_TODAY", lambda: expired)
    refused = ism_get_control("ism-1546")
    assert refused["data"] is None
    assert "ISM release list is unavailable" in refused["warnings"][0]
    assert "day limit" in refused["warnings"][0]
    # A named release is a published, unchanging catalogue, so it is still answered.
    pinned = ism_get_control("ism-1546", release="v2026.09.4")
    assert pinned["data"]["control_id"] == "ism-1546"


def test_failed_fetch_without_shipped_copy_is_unavailable(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_ISM_SNAPSHOT")
    source._TRANSPORT = httpx.MockTransport(lambda _request: httpx.Response(503))
    missing = ism_get_control("ism-1546", release="v2025.01.1")
    assert missing["data"] is None
    assert "is unavailable" in missing["warnings"][0]


def test_rebuild_shipped_snapshot_writes_full_releases(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_ISM_SNAPSHOT")
    catalog = (FIXTURES / "v2026.09.4" / "ISM_catalog.json").read_bytes()
    profile = (FIXTURES / "v2026.09.4" / "ISM_E8_ML1-baseline_profile.json").read_bytes()
    releases = json.dumps(
        [
            {"tag_name": "v2026.09.4", "published_at": "2026-09-03T23:39:10Z"},
            {"tag_name": "v2026.06.18", "published_at": "2026-06-18T09:23:52Z"},
            {"tag_name": "v2026.03.24", "published_at": "2026-03-24T08:35:10Z"},
        ]
    ).encode()

    def upstream(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.github.com":
            return httpx.Response(200, content=releases)
        if request.url.path.endswith("ISM_catalog.json"):
            return httpx.Response(200, content=catalog)
        return httpx.Response(200, content=profile)

    source._TRANSPORT = httpx.MockTransport(upstream)
    destination = tmp_path / "data"
    (destination / "v2025.12.9").mkdir(parents=True)
    (destination / "v2025.12.9" / "ISM_catalog.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(source, "_TODAY", lambda: date(2026, 10, 18))
    summary = source.rebuild_shipped_snapshot(destination, keep=2)
    assert summary["kept"] == ["v2026.09.4", "v2026.06.18"]
    assert summary["removed"] == ["v2025.12.9"]
    written = json.loads((destination / "releases.json").read_text())
    assert written["retrieved_on"] == "2026-10-18"
    assert len(list((destination / "v2026.06.18").glob("ISM_*-baseline_profile.json"))) == 8


def test_rebuild_shipped_snapshot_writes_nothing_on_failure(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_ISM_SNAPSHOT")
    source._TRANSPORT = httpx.MockTransport(lambda _request: httpx.Response(503))
    with pytest.raises(RuntimeError):
        source.rebuild_shipped_snapshot(tmp_path / "data")
    assert not (tmp_path / "data").exists()
