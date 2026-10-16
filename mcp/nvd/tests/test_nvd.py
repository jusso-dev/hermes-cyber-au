import asyncio
import json
import os
from pathlib import Path

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
