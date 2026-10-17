import os
import socket
from pathlib import Path

import cyberau_cisa_kev
import pytest
from cyberau_cisa_kev.source import kev_lookup, kev_recent, kev_search
from cyberau_common.egress import EgressDenied

SNAPSHOT = Path(__file__).resolve().parents[1] / "data" / "kev.json"


def setup_function():
    os.environ["CYBERAU_KEV_SNAPSHOT"] = str(SNAPSHOT)
    os.environ["CYBERAU_TODAY"] = "2026-10-16"


def test_lookup_and_search():
    found = kev_lookup(["CVE-2024-12345", "CVE-2099-0001"])
    assert found["cache"] == "snapshot"
    assert found["data"]["missing"] == ["CVE-2099-0001"]
    assert found["data"]["found"][0]["product"] == "Widget"
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
