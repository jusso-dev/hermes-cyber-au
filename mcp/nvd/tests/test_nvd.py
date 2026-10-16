import os
from pathlib import Path

from cyberau_nvd.source import nvd_cve_history, nvd_get_cve, nvd_search, schema_drift

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
