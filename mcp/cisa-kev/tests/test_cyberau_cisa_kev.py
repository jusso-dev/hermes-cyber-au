import os
from pathlib import Path

import cyberau_cisa_kev
from cyberau_cisa_kev.source import kev_lookup, kev_recent, kev_search
from cyberau_common.envelope import untrusted_text

SNAPSHOT = Path(__file__).resolve().parents[1] / "data" / "kev.json"


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
    recent = kev_recent(days=30)
    assert [row["cve_id"] for row in recent["data"]] == ["CVE-2024-12345"]
    matches = kev_search("log4")
    assert matches["data"][0]["cve_id"] == "CVE-2021-44228"
    assert cyberau_cisa_kev.connector().server_name == "kev"


def test_missing_arguments_are_warnings():
    assert kev_lookup()["warnings"]
    assert kev_search("x")["warnings"]
