import asyncio
import json
import os
from pathlib import Path

import cyberau_first_epss.source as source
import httpx
import pytest
from cyberau_common.server import build_server
from cyberau_first_epss.source import connector, epss_history, epss_scores, epss_top, schema_drift

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_journal_rotates_and_keeps_only_one_previous_generation(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(source, "_JOURNAL_BYTES", 40)
    for index in range(10):
        source._persist([{"cve": f"CVE-2026-{index:04d}"}])
    current = tmp_path / "epss-observations.jsonl"
    previous = tmp_path / "epss-observations.jsonl.1"
    assert json.loads(current.read_text())["cve"] == "CVE-2026-0009"
    assert json.loads(previous.read_text())["cve"] == "CVE-2026-0008"
    assert current.stat().st_size + previous.stat().st_size < 80


def test_journal_refuses_symlinked_archive(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    target = tmp_path / "evidence"
    target.write_text("preserve")
    (tmp_path / "epss-observations.jsonl.1").symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        source._persist([{"cve": "CVE-2026-0001"}])
    assert target.read_text() == "preserve"


def setup_function():
    os.environ["CYBERAU_OFFLINE"] = "1"
    os.environ["CYBERAU_EPSS_SNAPSHOT"] = str(FIXTURES / "epss_batch.json")


def test_scores_history_and_top():
    scores = epss_scores(["CVE-2024-3400"])
    assert scores["cache"] == "snapshot"
    assert scores["attribution"].startswith("FIRST EPSS")
    assert scores["data"][0]["epss"] == 0.96
    assert "<<untrusted source=first-epss>>" in scores["data"][0]["note"]
    os.environ["CYBERAU_EPSS_SNAPSHOT"] = str(FIXTURES / "epss_timeseries.json")
    history = epss_history("CVE-2024-3400")
    assert [row["date"] for row in history["data"]] == [
        "2026-09-16",
        "2026-10-14",
        "2026-10-15",
    ]
    os.environ["CYBERAU_EPSS_SNAPSHOT"] = str(FIXTURES / "epss_batch.json")
    top = epss_top(min_epss=0.5, limit=10)
    assert top["data"][0]["cve"] == "CVE-2024-3400"


def test_bad_payloads_warn():
    assert epss_scores([])["warnings"]
    drift = json.loads((FIXTURES / "epss_drift.json").read_text(encoding="utf-8"))
    assert schema_drift(drift)
    empty = json.loads((FIXTURES / "epss_unknown_cve.json").read_text(encoding="utf-8"))
    assert schema_drift(empty) is None
    os.environ["CYBERAU_EPSS_SNAPSHOT"] = str(FIXTURES / "epss_429.json")
    warned = epss_scores(["CVE-2024-3400"])
    assert warned["warnings"]
    os.environ["CYBERAU_EPSS_SNAPSHOT"] = str(FIXTURES / "epss_batch.json")
    missing = epss_scores(["CVE-2099-9999"], date="2000-01-01")
    assert missing["data"] == []
    assert missing["warnings"]
    above = epss_top(min_epss=0.99)
    assert above["data"] == []
    assert above["warnings"]
    assert epss_top(min_epss=1.5)["warnings"]


def test_advertised_schema_and_drift_probe():
    tools = {tool.name: tool for tool in asyncio.run(build_server(connector()).list_tools())}
    scores = tools["epss_scores"].inputSchema
    encoded = json.dumps(scores)
    assert scores["required"] == ["cve_ids"]
    assert "CVE-" in encoded
    assert "minItems" in encoded
    history = tools["epss_history"].inputSchema
    assert history["required"] == ["cve_id"]
    assert "maximum" in json.dumps(tools["epss_top"].inputSchema)
    os.environ["CYBERAU_EPSS_SNAPSHOT"] = str(FIXTURES / "epss_drift.json")
    probe = connector().health(live=False, check_schema=True)
    assert probe.ok is False


def test_http_retry_redirect_and_persist(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.delenv("CYBERAU_EPSS_SNAPSHOT", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    calls = {"n": 0}

    def retry(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "0"})
        assert request.url.params.get("cve") == "CVE-2024-3400"
        body = (FIXTURES / "epss_batch.json").read_bytes()
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(retry)
    try:
        found = epss_scores(["CVE-2024-3400"])
    finally:
        source._TRANSPORT = None
    assert found["data"][0]["epss"] == 0.96
    assert "CVE-2024-3400" in (tmp_path / "epss-observations.jsonl").read_text()

    def redirect(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.test/x"})

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "redirect"))
    source._TRANSPORT = httpx.MockTransport(redirect)
    try:
        refused = epss_scores(["CVE-2024-3400"])
    finally:
        source._TRANSPORT = None
    assert refused["warnings"]

    def top(request: httpx.Request) -> httpx.Response:
        assert request.url.params.get("order") == "!epss"
        body = (FIXTURES / "epss_batch.json").read_bytes()
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(top)
    try:
        ranked = epss_top(min_epss=0.5, limit=10)
    finally:
        source._TRANSPORT = None
    assert ranked["data"][0]["cve"] == "CVE-2024-3400"


def test_cassettes_replay():
    import vcr
    from vcr.serialize import deserialize
    from vcr.serializers import yamlserializer

    uris = {
        "epss_scores": "https://api.first.org/data/v1/epss?cve=CVE-2024-3400",
        "epss_history": "https://api.first.org/data/v1/epss?cve=CVE-2024-3400&scope=time-series",
        "epss_top": "https://api.first.org/data/v1/epss?epss-gt=0.5&order=%21epss&limit=10",
    }
    player = vcr.VCR(record_mode="none")
    for name, uri in uris.items():
        path = FIXTURES / f"{name}.yaml"
        requests, responses = deserialize(path.read_text(encoding="utf-8"), yamlserializer)
        assert requests and responses[0]["status"]["code"] == 200
        with player.use_cassette(str(path)):
            played = httpx.get(uri)
        assert played.status_code == 200
        assert played.json()["data"][0]["cve"] == "CVE-2024-3400"


def test_health_response_rejects_a_cached_payload(monkeypatch):
    payload = json.loads((FIXTURES / "epss_batch.json").read_text(encoding="utf-8"))
    for state in ("hit", "stale", "snapshot"):
        monkeypatch.setattr(source, "_fetch", lambda *_a, _s=state, **_k: (payload, _s, ""))
        result = source.health_response()
        assert result["ok"] is False
        assert result["body"] is None
        assert result["error_class"] == "stale_response"
    monkeypatch.setattr(source, "_fetch", lambda *_a, **_k: (payload, "miss", ""))
    live = source.health_response()
    assert live["ok"] is True
    assert live["body"] == payload


FIXTURE_VALUES = ("CVE-2024-3400", "v2026.10.15", "trimmed fixture", "0.96")


def _all_tools() -> dict:
    return {
        "epss_scores": epss_scores(["CVE-2024-3400"]),
        "epss_history": epss_history("CVE-2024-3400"),
        "epss_top": epss_top(min_epss=0.5, limit=10),
    }


def _assert_unavailable(results: dict) -> None:
    for name, result in results.items():
        assert result["data"] == [], name
        assert result["data_as_of"] is None, name
        assert any("is unavailable" in item for item in result["warnings"]), name
        text = json.dumps(result)
        for value in FIXTURE_VALUES:
            assert value not in text, (name, value)


def test_offline_without_override_serves_no_shipped_data(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_EPSS_SNAPSHOT", raising=False)
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    _assert_unavailable(_all_tools())


def test_failed_live_fetch_serves_no_shipped_data(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_EPSS_SNAPSHOT", raising=False)
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))

    def fail(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, content=b"unavailable")

    monkeypatch.setattr(source, "_TRANSPORT", httpx.MockTransport(fail))
    _assert_unavailable(_all_tools())


def test_override_snapshot_is_labelled():
    scores = epss_scores(["CVE-2024-3400"])
    assert any("operator-supplied EPSS snapshot" in item for item in scores["warnings"])


def test_offline_schema_check_without_override_reads_no_shipped_file(monkeypatch):
    monkeypatch.delenv("CYBERAU_EPSS_SNAPSHOT", raising=False)
    probe = connector().health(live=False, check_schema=True)
    assert probe.ok is True
    assert "no local copy" in probe.detail
