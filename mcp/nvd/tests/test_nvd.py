import asyncio
import json
import os
from pathlib import Path

import cyberau_nvd.source as nvd_source
import httpx
from cyberau_common.cache import HttpCache
from cyberau_common.secrets import redact, redact_headers
from cyberau_common.server import build_server
from cyberau_nvd.source import (
    CVE_API,
    connector,
    nvd_cve_history,
    nvd_get_cve,
    nvd_search,
    schema_drift,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def setup_function():
    os.environ["CYBERAU_OFFLINE"] = "1"
    os.environ["CYBERAU_NVD_SNAPSHOT"] = str(FIXTURES / "cve_CVE-2024-3400.json")


def test_get_and_search():
    record = nvd_get_cve("CVE-2024-3400")
    assert record["attribution"].startswith("This product uses data from the NVD")
    assert record["data"]["cvss"]["score"] == 10.0
    assert "<<untrusted source=nvd>>" in record["data"]["description"]
    found = nvd_search(keyword="injection", limit=5)
    assert found["data"][0]["cve_id"] == "CVE-2024-3400"


def test_history_and_bad_payloads():
    os.environ["CYBERAU_NVD_SNAPSHOT"] = str(FIXTURES / "nvd_history.json")
    history = nvd_cve_history("CVE-2024-3400")
    assert history["data"][0]["event"] == "Initial Analysis"
    os.environ["CYBERAU_NVD_SNAPSHOT"] = str(FIXTURES / "cve_CVE-2024-3400.json")
    missing = nvd_get_cve("CVE-2099-9999")
    assert missing["data"] is None
    assert missing["warnings"]
    os.environ["CYBERAU_NVD_SNAPSHOT"] = str(FIXTURES / "nvd_503.json")
    warned = nvd_get_cve("CVE-2024-3400")
    assert warned["warnings"]
    assert schema_drift({"vulnerabilities": [{"cve": {}}]})
    os.environ["CYBERAU_NVD_SNAPSHOT"] = str(FIXTURES / "nvd_history.json")
    other = nvd_cve_history("CVE-2099-9999")
    assert other["data"] == []
    assert other["warnings"]


def test_search_filters_and_schema():
    assert nvd_search(cvss_v3_severity="LOW")["data"] == []
    assert nvd_search(cpe_name="cpe:2.3:a:other:product")["data"] == []
    assert nvd_search(published_from="2099-01-01")["data"] == []
    assert nvd_search(kev_only=True)["data"] == []
    found = nvd_search(
        keyword="injection",
        cpe_name="palo_alto_networks:pan-os",
        published_from="2024-01-01",
        published_to="2024-12-31",
        cvss_v3_severity="CRITICAL",
    )
    assert found["data"][0]["cve_id"] == "CVE-2024-3400"
    assert nvd_search(limit=0)["warnings"]
    listed = asyncio.run(build_server(connector()).list_tools())
    tools = {tool.name: tool for tool in listed}
    encoded = json.dumps(tools["nvd_search"].inputSchema)
    assert "CRITICAL" in encoded
    assert "maximum" in encoded
    probe = connector().health(live=False, check_schema=True)
    os.environ["CYBERAU_NVD_SNAPSHOT"] = str(FIXTURES / "nvd_503.json")
    failed = connector().health(live=False, check_schema=True)
    assert probe.ok is True
    assert failed.ok is False


def test_offline_prefers_cache_and_redacts_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_NVD_SNAPSHOT", raising=False)
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    params = {"cveId": "CVE-2099-0001"}
    body = json.dumps(
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2099-0001",
                        "descriptions": [{"lang": "en", "value": "cached record"}],
                    }
                }
            ]
        }
    ).encode()
    key = cache.key("GET", CVE_API, params, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=body, ttl=86400)
    found = nvd_get_cve("CVE-2099-0001")
    assert found["cache"] in {"hit", "stale"}
    assert found["data"]["cve_id"] == "CVE-2099-0001"
    secret = "super-secret-value"
    assert secret not in redact(f"apiKey: {secret}")
    assert redact_headers({"apiKey": secret})["apiKey"] == "[REDACTED]"


def test_live_health_ignores_fresh_cache(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_NVD_SNAPSHOT", raising=False)
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    params = {"cveId": "CVE-2024-3400"}
    body = (FIXTURES / "cve_CVE-2024-3400.json").read_bytes()
    key = cache.key("GET", CVE_API, params, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=body, ttl=86400)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, content=body)

    nvd_source._TRANSPORT = httpx.MockTransport(handler)
    try:
        probe = connector().health(live=True)
    finally:
        nvd_source._TRANSPORT = None
    assert calls["n"] == 1
    assert probe.ok is True

    def fail(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503, content=b"unavailable")

    calls["n"] = 0
    nvd_source._TRANSPORT = httpx.MockTransport(fail)
    try:
        failed = connector().health(live=True)
    finally:
        nvd_source._TRANSPORT = None
    assert calls["n"] >= 1
    assert failed.ok is False
    assert failed.detail != "live ok"


def test_v3_severity_is_not_hidden_by_v4(tmp_path, monkeypatch):
    payload = json.loads((FIXTURES / "cve_CVE-2024-3400.json").read_text())
    cve = payload["vulnerabilities"][0]["cve"]
    cve["metrics"]["cvssMetricV31"] = [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
    cve["metrics"]["cvssMetricV40"] = [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
    path = tmp_path / "both.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("CYBERAU_NVD_SNAPSHOT", str(path))
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    assert nvd_search(cvss_v3_severity="HIGH")["data"][0]["cve_id"] == "CVE-2024-3400"
    assert nvd_search(cvss_v3_severity="LOW")["data"] == []


def test_nvd_vcr_config_filters_api_key(vcr_config):
    assert "apiKey" in vcr_config["filter_headers"]


FIXTURE_VALUES = ("CVE-2024-3400", "trimmed fixture", "Initial Analysis", "2026-10-16T00:00:00")


def _all_tools() -> dict:
    return {
        "nvd_get_cve": nvd_get_cve("CVE-2024-3400"),
        "nvd_search": nvd_search(keyword="injection"),
        "nvd_cve_history": nvd_cve_history("CVE-2024-3400"),
    }


def _assert_unavailable(results: dict) -> None:
    for name, result in results.items():
        assert result["data"] in (None, []), name
        assert any("is unavailable" in item for item in result["warnings"]), name
        text = json.dumps(result)
        for value in FIXTURE_VALUES:
            assert value not in text, (name, value)


def test_offline_without_override_serves_no_shipped_data(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_NVD_SNAPSHOT", raising=False)
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    _assert_unavailable(_all_tools())


def test_failed_live_fetch_serves_no_shipped_data(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_NVD_SNAPSHOT", raising=False)
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))

    def fail(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, content=b"unavailable")

    monkeypatch.setattr(nvd_source, "_TRANSPORT", httpx.MockTransport(fail))
    _assert_unavailable(_all_tools())


def test_override_snapshot_is_labelled():
    record = nvd_get_cve("CVE-2024-3400")
    assert record["cache"] == "snapshot"
    assert any("operator-supplied NVD snapshot" in item for item in record["warnings"])


def test_offline_schema_check_without_override_reads_no_shipped_file(monkeypatch):
    monkeypatch.delenv("CYBERAU_NVD_SNAPSHOT", raising=False)
    probe = connector().health(live=False, check_schema=True)
    assert probe.ok is True
    assert "no local copy" in probe.detail
