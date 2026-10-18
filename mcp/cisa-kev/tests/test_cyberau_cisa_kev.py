import json
import os
import socket
from pathlib import Path

import cyberau_cisa_kev
import pytest
from cyberau_cisa_kev.source import kev_lookup, kev_recent, kev_search
from cyberau_common.egress import EgressDenied
from cyberau_common.envelope import untrusted_text
from cyberau_common.http import HttpClient, HttpError

SNAPSHOT = Path(__file__).resolve().parent / "fixtures" / "kev.json"
FIXTURE_VALUES = (
    "CVE-2024-12345",
    "CVE-2021-44228",
    "Example widget flaw",
    "Log4Shell",
    "2026.10.16",
)


def setup_function():
    os.environ["CYBERAU_KEV_SNAPSHOT"] = str(SNAPSHOT)
    os.environ["CYBERAU_TODAY"] = "2026-10-16"


def test_lookup_and_search():
    found = kev_lookup(["CVE-2024-12345", "CVE-2099-0001"])
    assert found["cache"] == "snapshot"
    assert found["data"]["missing"] == ["CVE-2099-0001"]
    product = found["data"]["found"][0]["product"]
    description = found["data"]["found"][0]["description"]
    assert product == untrusted_text("Widget", "cisa-kev")
    assert description == untrusted_text("A trimmed catalogue entry for tests.", "cisa-kev")
    assert found["untrusted"] is True
    assert any("operator-supplied KEV snapshot" in item for item in found["warnings"])
    recent = kev_recent(days=30)
    assert [row["cve_id"] for row in recent["data"]] == ["CVE-2024-12345"]
    matches = kev_search("log4")
    assert matches["data"][0]["cve_id"] == "CVE-2021-44228"
    assert cyberau_cisa_kev.connector().server_name == "kev"


def test_missing_arguments_are_warnings():
    assert kev_lookup()["warnings"]
    assert kev_search("x")["warnings"]


def test_host_outside_the_allowlist_opens_no_socket(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_KEV_SNAPSHOT", raising=False)
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    allow = tmp_path / "allow.yaml"
    allow.write_text(
        "version: 1\nconnectors:\n  cisa-kev:\n    hosts: [example.com]\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_EGRESS_ALLOWLIST", str(allow))

    def opened(*_args, **_kwargs):
        raise AssertionError("socket opened")

    monkeypatch.setattr(socket, "getaddrinfo", opened)
    monkeypatch.setattr(socket, "create_connection", opened)
    with pytest.raises(EgressDenied):
        kev_lookup(["CVE-2024-12345"])


def _tools():
    return {
        "kev_lookup": kev_lookup(["CVE-2024-12345", "CVE-2021-44228"]),
        "kev_recent": kev_recent(days=3650),
        "kev_search": kev_search("widget"),
    }


def _assert_unavailable(results):
    for name, result in results.items():
        data = result["data"]
        if name == "kev_lookup":
            assert data == {"found": [], "missing": []}, name
        else:
            assert data == [], name
        assert result["data_as_of"] is None, name
        assert any("is unavailable" in item for item in result["warnings"]), name
        text = json.dumps(result)
        for value in FIXTURE_VALUES:
            assert value not in text, (name, value)


def test_offline_without_override_serves_no_shipped_data(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_KEV_SNAPSHOT", raising=False)
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    _assert_unavailable(_tools())


def test_failed_live_fetch_serves_no_shipped_data(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_KEV_SNAPSHOT", raising=False)
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))

    def failed(*_args, **_kwargs):
        raise HttpError("upstream status 503")

    monkeypatch.setattr(HttpClient, "_request", failed)
    results = _tools()
    _assert_unavailable(results)
    assert "503" in results["kev_lookup"]["warnings"][0]
