import asyncio
import hashlib
import ipaddress
import json
from datetime import date, timedelta
from pathlib import Path

import cyberau_au_regulatory.source as source
import httpx
import jsonschema
import pytest
from cyberau_au_regulatory.source import (
    CISC_PDF,
    CSA_TEXT,
    CYBER_REPORT,
    OAIC_QUICK,
    OAIC_SCHEME,
    aureg_deadline,
    aureg_obligation,
    connector,
    refresh_sources,
    schema_drift,
)
from cyberau_common.server import build_server

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SCHEMA = Path(__file__).resolve().parents[1] / "schema"
SNAPSHOT = sorted((Path(__file__).resolve().parents[1] / "data").glob("obligations-*.json"))[-1]
SNAPSHOT_DAY = date.fromisoformat(
    json.loads(SNAPSHOT.read_text(encoding="utf-8"))["retrieved_at"][:10]
)


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(float(seconds))
        self.now += float(seconds)


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.delenv("CYBERAU_AUREG_SNAPSHOT", raising=False)
    source._CLOCK = _Clock()
    source._RESOLVER = lambda _host: [ipaddress.ip_address("1.1.1.1")]
    source._TRANSPORT = None
    source._TODAY = lambda: SNAPSHOT_DAY + timedelta(days=1)
    yield
    source._CLOCK = None
    source._RESOLVER = None
    source._TRANSPORT = None
    source._TODAY = None


def _due(record: dict, name: str) -> dict:
    return {item["name"]: item for item in record["deadlines"]}[name]


def test_obligations_quotes_and_deadlines():
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    obligation_schema = json.loads((SCHEMA / "aureg_obligation.response.json").read_text())
    deadline_schema = json.loads((SCHEMA / "aureg_deadline.response.json").read_text())
    input_schema = json.loads((SCHEMA / "aureg_obligation.input.json").read_text())
    jsonschema.validate({"regime": "ndb"}, input_schema)

    listed = aureg_obligation("ndb")
    assert listed["cache"] == "snapshot"
    assert "not legal advice" in listed["attribution"]
    assert [row["trigger"] for row in listed["data"]] == ["suspected_breach", "eligible_breach"]
    by_quote = {row["trigger"]: row["quote"] for row in snapshot["obligations"]}
    for record in listed["data"]:
        jsonschema.validate(record, obligation_schema)
        assert "<<untrusted source=aureg>>" in record["quote"]
        assert "<<untrusted source=aureg>>" in record["rule"]
        raw = by_quote[record["trigger"]]
        assert raw in record["quote"]
        assert record["sha256"] == hashlib.sha256(raw.encode()).hexdigest()

    suspected = aureg_deadline("ndb", "suspected_breach", "2026-01-20T15:30:00+11:00")
    jsonschema.validate(suspected["data"][0], deadline_schema)
    assert _due(suspected["data"][0], "assessment")["due_at"] == "2026-02-19T15:30:00+11:00"
    eligible = aureg_deadline("ndb", "eligible_breach", "2026-01-20T15:30:00+11:00")
    assert _due(eligible["data"][0], "commissioner_statement")["due_at"] is None
    assert _due(eligible["data"][0], "individual_notice")["due_at"] is None

    critical = aureg_deadline("soci", "critical_incident", "2026-10-16T10:00:00+11:00")
    assert _due(critical["data"][0], "notification")["due_at"] == "2026-10-16T22:00:00+11:00"
    assert _due(critical["data"][0], "written_record")["due_at"] is None
    assert "84 hours" in _due(critical["data"][0], "written_record")["basis"]
    other = aureg_deadline("soci", "other_incident", "2026-07-01T08:00:00+10:00")
    assert _due(other["data"][0], "notification")["due_at"] == "2026-07-04T08:00:00+10:00"
    assert "48 hours" in _due(other["data"][0], "written_record")["basis"]

    paid = aureg_deadline("ransomware_payment", "payment", "2026-10-15T13:00:00Z")
    assert paid["data"][0]["aware_at"] == "2026-10-16T00:00:00+11:00"
    assert _due(paid["data"][0], "report")["due_at"] == "2026-10-19T00:00:00+11:00"
    assert "within 72 hours" in paid["data"][0]["quote"]
    stored = source._data_dir() / "aureg-obligations.jsonl"
    assert "suspected_breach" in stored.read_text(encoding="utf-8")


def test_empty_malformed_and_naive_time(monkeypatch):
    empty = aureg_obligation("soci", trigger="not_a_trigger")
    assert empty["data"] == []
    assert empty["warnings"]
    naive = aureg_deadline("ndb", "suspected_breach", "2026-07-01T08:00:00")
    assert "Australia/Sydney" in naive["warnings"][0]
    assert _due(naive["data"][0], "assessment")["due_at"] == "2026-07-31T08:00:00+10:00"
    invalid = aureg_deadline("ndb", "example", "example")
    assert invalid["data"] == []
    assert invalid["cache"] == "snapshot"
    assert invalid["warnings"]

    monkeypatch.setenv("CYBERAU_AUREG_SNAPSHOT", str(FIXTURES / "obligations_empty.json"))
    assert aureg_obligation("ndb")["data"] == []
    monkeypatch.setenv("CYBERAU_AUREG_SNAPSHOT", str(FIXTURES / "obligations_malformed.json"))
    broken = aureg_obligation("ndb")
    assert broken["warnings"]
    assert broken["data"] == []
    monkeypatch.setenv("CYBERAU_AUREG_SNAPSHOT", str(FIXTURES / "obligations_drift.json"))
    drifted = aureg_obligation("ndb")
    assert "schema drift" in drifted["warnings"][0]
    assert schema_drift(json.loads((FIXTURES / "obligations_drift.json").read_text()))


def test_schema_drift_health_and_tools(monkeypatch):
    assert connector().health(live=False, check_schema=True).ok is True
    monkeypatch.setenv("CYBERAU_AUREG_SNAPSHOT", str(FIXTURES / "obligations_drift.json"))
    failed = connector().health(live=False, check_schema=True)
    assert failed.ok is False
    assert "quote" in failed.detail
    from cyberau_common.cli import main

    assert main(["health", "au-regulatory", "--schema-drift"]) == 1

    tools = {tool.name: tool for tool in asyncio.run(build_server(connector()).list_tools())}
    assert tools["aureg_obligation"].annotations.readOnlyHint is True
    assert tools["aureg_deadline"].inputSchema["required"] == ["regime", "trigger", "aware_at"]
    called = asyncio.run(
        build_server(connector()).call_tool(
            "aureg_deadline",
            {"regime": "ndb", "trigger": "example", "aware_at": "example"},
        )
    )
    text = called[0][0].text if isinstance(called, tuple) else called[0].text
    assert "not legal advice" in text


def test_http_errors_retry_timeout_and_egress(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    pages = {
        OAIC_QUICK: (FIXTURES / "oaic_quick_ref.html").read_bytes(),
        OAIC_SCHEME: (FIXTURES / "oaic_quick_ref.html").read_bytes(),
        CYBER_REPORT: (FIXTURES / "cyber_report_page.html").read_bytes(),
        CISC_PDF: (FIXTURES / "cisc_ncsi_guidance.pdf").read_bytes(),
        CSA_TEXT: b"<html><p>A ransomware payment is due within 72 hours.</p></html>",
    }

    def ok(request: httpx.Request) -> httpx.Response:
        body = pages[str(request.url)]
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(ok)
    refreshed = refresh_sources()
    assert refreshed["warnings"] == []
    assert all(row["ok"] for row in refreshed["data"])

    calls = {"n": 0}

    def limited(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "0"})
        return httpx.Response(200, content=pages[CSA_TEXT])

    source._CLOCK = _Clock()
    source._TRANSPORT = httpx.MockTransport(limited)
    retried = refresh_sources(urls=[CSA_TEXT], force=True)
    assert retried["data"][0]["ok"] is True
    assert calls["n"] >= 2
    assert 0.0 in source._CLOCK.slept

    source._TRANSPORT = httpx.MockTransport(
        lambda _request: httpx.Response(403, content=b"refused")
    )
    refused = refresh_sources(urls=[CSA_TEXT], force=True)
    assert "403" in refused["warnings"][0]
    assert "env var" in refused["warnings"][0]

    source._TRANSPORT = httpx.MockTransport(
        lambda _request: httpx.Response(401, content=b"refused")
    )
    denied = refresh_sources(urls=[OAIC_QUICK], force=True)
    assert "401" in denied["warnings"][0]
    assert "env var" in denied["warnings"][0]

    source._CLOCK = _Clock()
    source._TRANSPORT = httpx.MockTransport(
        lambda _request: httpx.Response(200, content=pages[CSA_TEXT])
    )
    assert refresh_sources(urls=[CSA_TEXT], force=True, ttl=0)["data"][0]["ok"] is True

    def timed_out(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("timed out")

    source._TRANSPORT = httpx.MockTransport(timed_out)
    stale = refresh_sources(urls=[CSA_TEXT])
    assert stale["data"][0]["ok"] is True
    assert stale["data"][0]["cache"] == "stale"

    source._TRANSPORT = httpx.MockTransport(
        lambda _request: httpx.Response(302, headers={"location": "https://evil.example/stolen"})
    )
    blocked = refresh_sources(urls=[CYBER_REPORT], force=True)
    assert blocked["warnings"]
    assert "evil.example" in blocked["warnings"][0]

    source._TRANSPORT = httpx.MockTransport(lambda _request: httpx.Response(200, content=b"{}"))
    malformed = refresh_sources(urls=[OAIC_QUICK], force=True)
    assert malformed["warnings"]
    assert "schema drift" in malformed["warnings"][0]
    source._TRANSPORT = httpx.MockTransport(
        lambda _request: httpx.Response(200, content=b"not a pdf")
    )
    pdf = refresh_sources(urls=[CISC_PDF], force=True)
    assert "pdf" in pdf["warnings"][0]


def test_live_health_uses_one_call(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    calls = {"n": 0}
    body = b"<html>ransomware within 72 hours</html>"

    def ok(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(ok)
    assert connector().health(live=True).ok is True
    assert calls["n"] == 1

    source._TRANSPORT = httpx.MockTransport(
        lambda _request: httpx.Response(503, content=b"unavailable")
    )
    failed = connector().health(live=True)
    assert failed.ok is False
    assert "503" in failed.detail


def test_cassettes_replay():
    import vcr

    player = vcr.VCR(record_mode="none")
    samples = {
        "aureg_obligation.yaml": "https://www.legislation.gov.au/C2024A00098/latest/text",
        "aureg_deadline.yaml": "https://www.legislation.gov.au/C2018A00029/latest/text",
    }
    for name, uri in samples.items():
        with player.use_cassette(str(FIXTURES / name)):
            played = httpx.get(uri)
        assert played.status_code == 200
        assert "hours" in played.text


def test_snapshot_answers_warn_they_are_not_live():
    listed = aureg_obligation("soci", "critical_incident")
    due = aureg_deadline("soci", "critical_incident", "2026-10-16T10:00:00+11:00")
    for record in (listed, due):
        assert record["data"]
        assert record["cache"] == "snapshot"
        assert record["data_as_of"] == SNAPSHOT_DAY.isoformat()
        assert any(
            f"shipped Australian reporting obligations snapshot dated {SNAPSHOT_DAY.isoformat()}"
            in note
            and "not a live fetch" in note
            for note in record["warnings"]
        )
        assert any("amendments made since the snapshot date" in note for note in record["warnings"])


def _expired_answers() -> list[dict]:
    return [
        aureg_obligation("soci", "critical_incident"),
        aureg_obligation("ndb"),
        aureg_deadline("soci", "critical_incident", "2026-10-16T10:00:00+11:00"),
    ]


def test_expired_shipped_snapshot_is_unavailable():
    source._TODAY = lambda: SNAPSHOT_DAY + timedelta(days=source.SNAPSHOT_MAX_AGE_DAYS + 1)
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    for record in _expired_answers():
        assert record["data"] == []
        assert record["cache"] == "snapshot"
        assert record["data_as_of"] is None
        assert any("is unavailable" in note for note in record["warnings"])
        assert any("181 days old" in note for note in record["warnings"])
        text = json.dumps(record)
        for row in snapshot["obligations"]:
            assert row["citation"] not in text


def test_expired_shipped_snapshot_is_unavailable_when_live_fails(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    source._TRANSPORT = httpx.MockTransport(lambda request: httpx.Response(503))
    source._TODAY = lambda: SNAPSHOT_DAY + timedelta(days=source.SNAPSHOT_MAX_AGE_DAYS + 1)
    for record in _expired_answers():
        assert record["data"] == []
        assert any("is unavailable" in note for note in record["warnings"])


def test_synthetic_shipped_snapshot_is_refused(monkeypatch, tmp_path):
    package = tmp_path / "package"
    (package / "data").mkdir(parents=True)
    document = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    document["note"] = "Synthetic obligations invented for tests"
    (package / "data" / "obligations-2026-10-17.json").write_text(
        json.dumps(document), encoding="utf-8"
    )
    monkeypatch.setattr(source, "_PACKAGE", package)
    record = aureg_obligation("ndb")
    assert record["data"] == []
    assert any("looks like test data" in note for note in record["warnings"])


def test_operator_snapshot_is_labelled_without_an_age_limit(monkeypatch):
    monkeypatch.setenv("CYBERAU_AUREG_SNAPSHOT", str(SNAPSHOT))
    source._TODAY = lambda: SNAPSHOT_DAY + timedelta(days=1000)
    record = aureg_obligation("ndb")
    assert record["data"]
    assert record["data_as_of"] == SNAPSHOT_DAY.isoformat()
    assert any("operator-supplied" in note for note in record["warnings"])


def test_hour_deadlines_are_elapsed_hours_across_sydney_daylight_saving():
    # DST starts 2026-10-04 (clocks forward): 72 elapsed hours is 13:00 local.
    start = aureg_deadline("soci", "other_incident", "2026-10-03T12:00:00+10:00")
    assert _due(start["data"][0], "notification")["due_at"] == "2026-10-06T13:00:00+11:00"
    # DST ends 2026-04-05 (clocks back): 72 elapsed hours is 11:00 local.
    end = aureg_deadline("soci", "other_incident", "2026-04-04T12:00:00+11:00")
    assert _due(end["data"][0], "notification")["due_at"] == "2026-04-07T11:00:00+10:00"


def test_deadline_basis_and_citation_are_untrusted_wrapped():
    due = aureg_deadline("soci", "critical_incident", "2026-10-16T10:00:00+11:00")
    record = due["data"][0]
    assert record["citation"].startswith("<<untrusted source=aureg>>")
    for item in record["deadlines"]:
        assert item["basis"].startswith("<<untrusted source=aureg>>")


def test_schema_drift_checks_every_record():
    good = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    assert schema_drift(good) is None
    del good["obligations"][-1]["quote"]
    assert "quote" in schema_drift(good)
