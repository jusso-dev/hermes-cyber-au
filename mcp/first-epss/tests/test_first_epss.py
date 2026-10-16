import json
import os
from pathlib import Path

from cyberau_first_epss.source import epss_history, epss_scores, epss_top, schema_drift

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
    assert len(history["data"]) == 2
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
