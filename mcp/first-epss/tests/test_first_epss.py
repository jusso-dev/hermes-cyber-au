import asyncio
import json
import os
from pathlib import Path

import cyberau_first_epss.source as source
import httpx
from cyberau_common.server import build_server
from cyberau_first_epss.source import connector, epss_history, epss_scores, epss_top, schema_drift

FIXTURES = Path(__file__).resolve().parent / "fixtures"


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
