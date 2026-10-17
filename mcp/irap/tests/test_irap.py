import asyncio
import hashlib
import json
import random
import sqlite3
from pathlib import Path

import cyberau_irap.source as source
import httpx
import jsonschema
import pytest
from cyberau_common.server import build_server
from cyberau_irap.source import (
    connector,
    irap_consumer_checklist,
    irap_search_guidance,
    schema_drift,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ROOT = Path(__file__).resolve().parents[1]
TIMELINES = (
    "Define assessment timelines (start / end dates and milestones) "
    "to be agreed with the IRAP assessor."
)
GUIDE = (
    "https://www.cyber.gov.au/business-government/protecting-devices-systems/"
    "assessment-evaluation-programs/irap/irap-consumer-guide"
)


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_IRAP_SNAPSHOT", str(FIXTURES))
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    source._NOW = 0.0
    source._RNG = lambda: 0.0
    source._TRANSPORT = None
    yield
    source._NOW = None
    source._RNG = random.random
    source._TRANSPORT = None


def test_search_and_checklist_quote_the_guide():
    found = irap_search_guidance("three quotes")
    assert found["cache"] == "snapshot"
    assert found["data"]["coverage"] == "quoted"
    assert found["data"]["assessment"] is False
    assert found["data"]["endorsed_by_asd"] is False
    assert "not an IRAP assessment" in found["attribution"]
    assert "not endorsed by ASD" in found["attribution"]
    assert any("three quotes" in row["sentence"] for row in found["data"]["matches"])
    assert "<<untrusted source=irap>>" in found["data"]["matches"][0]["sentence"]

    checks = irap_consumer_checklist()
    assert checks["attribution"] == found["attribution"]
    assert [row["paragraph_id"] for row in checks["data"]] == [
        "timelines",
        "boundary",
        "onboarding",
        "personnel",
        "documents",
        "extra-evidence",
    ]
    first = checks["data"][0]
    assert first["kind"] == "check"
    assert first["assessment"] is False
    assert first["endorsed_by_asd"] is False
    assert first["url"] == GUIDE
    assert first["retrieved"] == "2026-10-16"
    assert first["sha256"] == hashlib.sha256(TIMELINES.encode()).hexdigest()
    assert "<<untrusted source=irap>>" in first["sentence"]
    assert "Define assessment timelines" in first["sentence"]
    linked = irap_search_guidance("assessment timelines")
    assert any(row["paragraph_id"] == "timelines" for row in linked["data"]["matches"])

    schemas = ROOT / "schema"
    envelope = {
        "type": "object",
        "required": ["source", "retrieved_at", "cache", "data", "untrusted", "attribution"],
        "properties": {
            "source": {"type": "string"},
            "retrieved_at": {"type": "string"},
            "cache": {"type": "string"},
            "data": {},
            "untrusted": {"const": True},
            "attribution": {"type": "string"},
            "warnings": {"type": "array"},
        },
    }
    search_schema = json.loads((schemas / "irap_search_guidance.response.json").read_text())
    check_schema = json.loads((schemas / "irap_consumer_checklist.response.json").read_text())
    input_schema = json.loads((schemas / "irap_search_guidance.input.json").read_text())
    empty_schema = json.loads((schemas / "irap_consumer_checklist.input.json").read_text())
    jsonschema.Draft202012Validator.check_schema(input_schema)
    jsonschema.Draft202012Validator.check_schema(empty_schema)
    jsonschema.validate({"query": "three quotes"}, input_schema)
    jsonschema.validate({}, empty_schema)
    for payload in (found, checks):
        jsonschema.validate(payload, envelope)
    jsonschema.validate(found["data"], search_schema)
    jsonschema.validate(checks["data"], check_schema)


def test_unanswered_question_is_not_covered():
    query = (FIXTURES / "question_not_answered").read_text(encoding="utf-8").strip()
    result = irap_search_guidance(query)
    assert result["data"]["coverage"] == "not covered"
    assert result["data"]["matches"] == []
    assert result["data"]["assessment"] is False
    assert "not covered" in result["warnings"]
    assert irap_search_guidance("x")["warnings"]


def test_stopword_only_queries_are_not_covered():
    for query in ("should", "that the", "What should this do?"):
        found = irap_search_guidance(query)
        assert found["data"]["coverage"] == "not covered", query
        assert found["data"]["matches"] == []
    assert irap_search_guidance("assessment timelines")["data"]["coverage"] == "quoted"


def test_snapshot_is_labelled_as_search_index_passages():
    for result in (irap_search_guidance("three quotes"), irap_consumer_checklist()):
        note = [w for w in result["warnings"] if w.startswith("Shipped snapshot")]
        assert len(note) == 1
        assert "search index" in note[0]
        assert "16 October 2026" in note[0]
        assert "not a full fetch" in note[0]
    missed = irap_search_guidance("What dollar amount does ASD charge?")
    assert any("search index" in warning for warning in missed["warnings"])


def test_page_chrome_is_not_a_checklist_item():
    html = (
        "<nav><ul><li>Home page for the Australian Cyber Security Centre website</li></ul></nav>"
        "<main><ul><li>Agree the assessment boundary with the IRAP assessor first.</li></ul></main>"
        "<footer><ul><li>We acknowledge the Traditional Custodians of Country</li></ul></footer>"
    )
    rows = source._parse(html, "consumer-guide", GUIDE)
    assert [row["sentence"] for row in rows] == [
        "Agree the assessment boundary with the IRAP assessor first."
    ]


def test_empty_checklist_and_malformed_page(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_IRAP_SNAPSHOT", str(FIXTURES / "empty"))
    empty = irap_consumer_checklist()
    assert empty["data"] == []
    assert any("empty" in warning for warning in empty["warnings"])

    broken = tmp_path / "broken"
    broken.mkdir()
    overview = (FIXTURES / "irap_overview.html").read_text(encoding="utf-8")
    (broken / "irap_overview.html").write_text(overview, encoding="utf-8")
    (broken / "irap_consumer_guide.html").write_text(
        (FIXTURES / "malformed.html").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_IRAP_SNAPSHOT", str(broken))
    warned = irap_consumer_checklist()
    assert warned["data"] == []
    assert warned["warnings"]
    assert "schema drift" in warned["warnings"][0]
    assert schema_drift((FIXTURES / "drift" / "irap_consumer_guide.html").read_text())


def test_bidi_text_is_wrapped(tmp_path, monkeypatch):
    snapshot = tmp_path / "bidi"
    snapshot.mkdir()
    (snapshot / "irap_overview.html").write_text(
        (FIXTURES / "irap_overview.html").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (snapshot / "irap_consumer_guide.html").write_text(
        """
        <article data-page="consumer-guide" data-url="https://www.cyber.gov.au/irap"
          data-retrieved="2026-10-16">
          <p data-id="bidi" data-kind="paragraph"
            data-sentence="Widget guidance \u202e hidden from the consumer."></p>
        </article>
        """,
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_IRAP_SNAPSHOT", str(snapshot))
    found = irap_search_guidance("Widget guidance")
    sentence = found["data"]["matches"][0]["sentence"]
    assert "\u202e" not in sentence
    assert "<<untrusted source=irap>>" in sentence
    assert "hidden from the consumer" in sentence


def test_schema_and_live_health(tmp_path, monkeypatch):
    tools = {tool.name: tool for tool in asyncio.run(build_server(connector()).list_tools())}
    assert tools["irap_search_guidance"].inputSchema["required"] == ["query"]
    assert "minLength" in json.dumps(tools["irap_search_guidance"].inputSchema)
    assert tools["irap_consumer_checklist"].annotations.readOnlyHint is True
    probe = connector().health(live=False, check_schema=True)
    assert probe.ok is True
    monkeypatch.setenv("CYBERAU_IRAP_SNAPSHOT", str(FIXTURES / "drift"))
    failed = connector().health(live=False, check_schema=True)
    assert failed.ok is False
    assert "data-sentence" in failed.detail

    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_IRAP_SNAPSHOT")
    pages = {
        "/irap": (FIXTURES / "irap_overview.html").read_bytes(),
        GUIDE.removeprefix("https://www.cyber.gov.au"): (
            FIXTURES / "irap_consumer_guide.html"
        ).read_bytes(),
    }
    calls = {"n": 0}

    def ok(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, content=pages[request.url.path])

    source._TRANSPORT = httpx.MockTransport(ok)
    live = connector().health(live=True, check_schema=True)
    assert calls["n"] == 2
    assert live.ok is True

    def unavailable(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503, content=b"unavailable")

    calls["n"] = 0
    source._TRANSPORT = httpx.MockTransport(unavailable)
    down = connector().health(live=True)
    assert calls["n"] >= 1
    assert down.ok is False
    assert "503" in down.detail


def test_auth_errors_name_the_offline_env(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_IRAP_SNAPSHOT")
    for status in (401, 403):

        def denied(_request: httpx.Request, status=status) -> httpx.Response:
            return httpx.Response(status, content=b"no")

        source._TRANSPORT = httpx.MockTransport(denied)
        result = irap_consumer_checklist()
        assert result["data"]
        assert result["data"][0]["assessment"] is False
        warning = " ".join(result["warnings"])
        assert str(status) in warning
        assert "CYBERAU_OFFLINE" in warning
        source._NOW = 100.0


def test_retry_after_redirect_and_timeout(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_IRAP_SNAPSHOT")
    guide = (FIXTURES / "irap_consumer_guide.html").read_bytes()
    slept = []
    original = source._sleep

    def spy(seconds):
        slept.append(seconds)
        original(seconds)

    monkeypatch.setattr(source, "_sleep", spy)
    calls = {"n": 0}

    def retry(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "2"})
        return httpx.Response(200, content=guide)

    source._TRANSPORT = httpx.MockTransport(retry)
    found = irap_consumer_checklist()
    assert found["data"][0]["paragraph_id"] == "timelines"
    assert calls["n"] >= 2
    assert any(item == 2 for item in slept)

    def redirect(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/stolen"})

    source._NOW = 100.0
    for path in tmp_path.glob("http_cache.sqlite*"):
        path.unlink()
    source._TRANSPORT = httpx.MockTransport(redirect)
    refused = irap_consumer_checklist()
    warning = " ".join(refused["warnings"])
    assert "evil.example" in warning or "allow" in warning.lower()

    source._NOW = 200.0
    source._TRANSPORT = httpx.MockTransport(lambda _request: httpx.Response(200, content=guide))
    assert irap_consumer_checklist()["data"]
    for path in tmp_path.glob("http_cache.sqlite*"):
        path.unlink()

    def timeout(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    source._NOW = 300.0
    source._TRANSPORT = httpx.MockTransport(timeout)
    stale = irap_consumer_checklist()
    assert stale["cache"] == "stale"
    assert stale["data"]
    assert "timed out" in " ".join(stale["warnings"])


def test_http11_fallback_and_spacing(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_IRAP_SNAPSHOT")
    overview = (FIXTURES / "irap_overview.html").read_bytes()
    guide = (FIXTURES / "irap_consumer_guide.html").read_bytes()

    def http11(request: httpx.Request) -> httpx.Response:
        if "HTTP/1.1 fallback" not in request.headers.get("user-agent", ""):
            raise httpx.ConnectError("connection reset")
        assert "hermes-cyber-au" in request.headers.get("user-agent", "")
        if request.url.path == "/irap":
            return httpx.Response(200, content=overview)
        return httpx.Response(200, content=guide)

    source._TRANSPORT = httpx.MockTransport(http11)
    source._NOW = 0.0
    found = irap_search_guidance("three quotes")
    assert found["data"]["coverage"] == "quoted"
    assert source._NOW >= 5
    db = sqlite3.connect(Path(source._data_dir()) / "irap_guidance.sqlite")
    method = db.execute("SELECT method FROM pages WHERE page = 'consumer-guide'").fetchone()[0]
    assert method == "http11"


def test_history_keeps_sentences_that_leave_the_page(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_IRAP_SNAPSHOT")
    overview = (FIXTURES / "irap_overview.html").read_bytes()
    guide = (FIXTURES / "irap_consumer_guide.html").read_text(encoding="utf-8")
    extra = (
        '<p data-id="quay" data-kind="paragraph" '
        'data-sentence="Unique stored guidance sentence about quay widgets."></p>'
    )
    first = guide.replace("</article>", extra + "</article>")
    bodies = {"guide": first.encode()}

    def live(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/irap":
            return httpx.Response(200, content=overview)
        return httpx.Response(200, content=bodies["guide"])

    source._TRANSPORT = httpx.MockTransport(live)
    assert irap_search_guidance("quay widgets")["data"]["coverage"] == "quoted"
    bodies["guide"] = guide.encode()
    for path in Path(source._data_dir()).glob("http_cache.sqlite*"):
        path.unlink()
    source._NOW = 100.0
    later = irap_search_guidance("quay widgets")
    assert later["data"]["coverage"] == "not covered"
    db = sqlite3.connect(Path(source._data_dir()) / "irap_guidance.sqlite")
    kept = db.execute("SELECT sentence FROM guidance WHERE paragraph_id = 'quay'").fetchone()
    assert kept is not None
    assert "quay widgets" in kept[0]


def test_plain_html_paragraph_is_quoted(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_IRAP_SNAPSHOT")
    page = (
        "<html><body><p>IRAP assessors do not accredit, endorse or register "
        "systems on our behalf.</p></body></html>"
    )
    source._TRANSPORT = httpx.MockTransport(
        lambda _request: httpx.Response(200, content=page.encode())
    )
    found = irap_consumer_checklist()
    assert found["warnings"]
    listed = irap_search_guidance("do not accredit")
    match = listed["data"]["matches"][0]
    assert match["assessment"] is False
    assert match["sha256"]
    assert "<<untrusted source=irap>>" in match["sentence"]


def test_cassettes_have_no_secrets_and_replay():
    import vcr
    from vcr.serialize import deserialize
    from vcr.serializers import yamlserializer

    player = vcr.VCR(record_mode="none")
    uris = {
        "irap_search_guidance": "https://www.cyber.gov.au/irap",
        "irap_consumer_checklist": (
            "https://www.cyber.gov.au/business-government/protecting-devices-systems/"
            "assessment-evaluation-programs/irap/irap-consumer-guide"
        ),
    }
    for path in FIXTURES.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        assert "Bearer " not in text
        assert "api_key" not in text.lower()
        assert "authorization:" not in text.lower()
    for name, uri in uris.items():
        cassette = FIXTURES / f"{name}.yaml"
        requests, responses = deserialize(cassette.read_text(encoding="utf-8"), yamlserializer)
        assert requests and responses[0]["status"]["code"] == 200
        with player.use_cassette(str(cassette)):
            played = httpx.get(uri)
        assert played.status_code == 200
        assert "data-sentence" in played.text
