"""AusCERT member URL feed connector. Every feed body is a synthetic fixture."""

import asyncio
import ipaddress
import json
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import cyberau_auscert_member.source as source
import httpx
import jsonschema
import pytest
import yaml
from cyberau_auscert_member.source import (
    ATTRIBUTION,
    DOCTOR_NOTE,
    FEED_ENV,
    OPERATOR_NOTE,
    SNAPSHOT_ENV,
    TERMS,
    TOKEN_ENV,
    auscert_url_feed_lookup,
    auscert_url_feed_status,
    connector,
    parse_feed,
    schema_drift,
)
from cyberau_common.server import build_server

PACKAGE = Path(__file__).resolve().parents[1]
MCP = PACKAGE.parent
REPO = MCP.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
TOOLS = ("auscert_url_feed_lookup", "auscert_url_feed_status")
FEED = "https://feeds.example.com/auscert/malurl.txt"
TOKEN = "test-only-auscert-feed-token-not-a-secret"
LISTED = "https://login.bank-example.example.com/secure/verify"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    for name in (FEED_ENV, TOKEN_ENV, SNAPSHOT_ENV, "CYBERAU_OFFLINE", "CYBERAU_AUDIT_LOG_PATH"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "data"))
    source._RESOLVER = lambda _host: [ipaddress.ip_address("93.184.216.34")]
    source._SLEEP = lambda _seconds: None
    source._LIMIT_SLEEP = lambda _seconds: None
    yield
    source._TRANSPORT = None
    source._RESOLVER = None
    source._SLEEP = time.sleep
    source._LIMIT_SLEEP = time.sleep
    source._RETRIES = 1


def _arm(monkeypatch, *, token: bool = True) -> None:
    monkeypatch.setenv(FEED_ENV, FEED)
    if token:
        monkeypatch.setenv(TOKEN_ENV, TOKEN)


def _serve(body: str | bytes, *, status: int = 200, headers=None, seen: list | None = None):
    content = body.encode() if isinstance(body, str) else body

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        return httpx.Response(status, content=content, headers=headers or {})

    source._TRANSPORT = httpx.MockTransport(handler)


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _valid(tool: str, payload: dict) -> None:
    jsonschema.validate(payload["data"], json.loads(_schema(f"{tool}.response.json")))
    assert payload["untrusted"] is True
    assert payload["attribution"] == ATTRIBUTION


def _schema(name: str) -> str:
    return (PACKAGE / "schema" / name).read_text(encoding="utf-8")


def _call(tool: str, arguments: dict) -> dict:
    """Call through the MCP server, validating the input against its schema."""
    jsonschema.validate(arguments, json.loads(_schema(f"{tool}.input.json")))
    return _payload(asyncio.run(build_server(connector()).call_tool(tool, arguments)))


def _payload(result) -> dict:
    if isinstance(result, dict):
        return result
    if isinstance(result, list | tuple):
        for item in result:
            if isinstance(item, dict) and "source" in item:
                return item
        for item in result:
            found = _payload(item) if isinstance(item, list | tuple | dict) else None
            if found:
                return found
            text = getattr(item, "text", None)
            if text:
                return json.loads(text)
    structured = getattr(result, "structured_content", None) or getattr(
        result, "structuredContent", None
    )
    if isinstance(structured, dict):
        return structured.get("result", structured) if "source" not in structured else structured
    content = getattr(result, "content", None)
    if content:
        return _payload(list(content))
    raise AssertionError(f"cannot read tool result {type(result)!r}")


# Tools, schemas and annotations.


def test_tools_are_read_only_and_named_as_in_the_issue():
    listed = asyncio.run(build_server(connector()).list_tools())
    assert sorted(tool.name for tool in listed) == sorted(TOOLS)
    for tool in listed:
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.open_world_hint is True
        assert tool.annotations.destructive_hint is False
        assert f"mcp__auscertm__{tool.name}" in {
            "mcp__auscertm__auscert_url_feed_lookup",
            "mcp__auscertm__auscert_url_feed_status",
        }
        assert len(f"mcp__auscertm__{tool.name}") == 38
        schema = json.loads(_schema(f"{tool.name}.input.json"))
        jsonschema.Draft202012Validator.check_schema(schema)
    lookup_schema = json.loads(_schema("auscert_url_feed_lookup.input.json"))
    assert lookup_schema == {
        "type": "object",
        "additionalProperties": False,
        "properties": {"value": {"type": "string", "minLength": 3}},
        "required": ["value"],
    }
    assert json.loads(_schema("auscert_url_feed_status.input.json")) == {
        "type": "object",
        "additionalProperties": False,
        "properties": {},
        "required": [],
    }


# Happy path.


def test_happy_path_for_every_tool(monkeypatch):
    _arm(monkeypatch)
    seen: list[httpx.Request] = []
    _serve(_fixture("url_feed_synthetic.txt"), seen=seen)
    found = _call("auscert_url_feed_lookup", {"value": LISTED + "/"})
    _valid("auscert_url_feed_lookup", found)
    assert found["cache"] == "miss"
    assert found["data"]["listed"] is True
    assert found["data"]["kind"] == "url"
    assert found["data"]["match_count"] == 1
    assert found["data"]["entries_checked"] == 4
    assert found["data"]["matches"][0]["match"] == "exact"
    assert seen[0].url.host == "feeds.example.com"
    assert seen[0].headers["authorization"] == f"Bearer {TOKEN}"

    domain = _call("auscert_url_feed_lookup", {"value": "example.org"})
    _valid("auscert_url_feed_lookup", domain)
    assert domain["cache"] == "hit"
    assert domain["data"]["kind"] == "domain"
    assert [item["match"] for item in domain["data"]["matches"]] == ["subdomain"]
    refanged = _call("auscert_url_feed_lookup", {"value": "mygov-refund[.]example.org"})
    assert refanged["data"]["matches"][0]["match"] == "exact"

    status = _call("auscert_url_feed_status", {})
    _valid("auscert_url_feed_status", status)
    assert status["data"]["configured"] is True
    assert status["data"]["entries"] == 4
    assert status["data"]["format"] == "text"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", status["data"]["fetched_at"])
    assert len(seen) == 1, "the feed is fetched once and then served from the one hour cache"


def test_csv_feed_with_a_url_column(monkeypatch):
    _arm(monkeypatch, token=False)
    seen: list[httpx.Request] = []
    _serve(_fixture("url_feed_synthetic.csv"), seen=seen)
    found = auscert_url_feed_lookup("parcel-tracking.example.net")
    _valid("auscert_url_feed_lookup", found)
    match = found["data"]["matches"][0]
    assert "2026-11-02" in match["first_seen"]
    assert "phishing" in match["category"]
    assert "authorization" not in seen[0].headers
    status = auscert_url_feed_status()
    assert status["data"]["format"] == "csv"
    assert status["data"]["entries"] == 3


def test_not_listed_value_says_so(monkeypatch):
    _arm(monkeypatch)
    _serve(_fixture("url_feed_synthetic.txt"))
    missing = auscert_url_feed_lookup("https://unlisted.example.com/")
    _valid("auscert_url_feed_lookup", missing)
    assert missing["data"]["listed"] is False
    assert missing["data"]["matches"] == []
    assert "not listed in the member URL feed" in missing["warnings"]


def test_bad_input_is_a_warning():
    for bad in ("ab", "ftp://example.com/x", "not a host", "https://user:pw@example.com/"):
        result = auscert_url_feed_lookup(bad)
        assert result["data"] is None
        assert result["warnings"]


# Empty and malformed upstream payloads.


def test_empty_feed(monkeypatch):
    _arm(monkeypatch)
    _serve(_fixture("url_feed_empty.txt"))
    found = auscert_url_feed_lookup("example.com")
    _valid("auscert_url_feed_lookup", found)
    assert found["data"]["listed"] is False
    assert found["data"]["entries_checked"] == 0
    status = auscert_url_feed_status()
    assert status["data"]["entries"] == 0
    assert "the member URL feed has no entries" in status["warnings"]


def test_malformed_payload_is_a_warning_not_an_exception(monkeypatch):
    _arm(monkeypatch)
    _serve(_fixture("url_feed_malformed.txt"))
    found = auscert_url_feed_lookup("example.com")
    assert found["data"] is None
    assert "schema drift" in found["warnings"][0]
    _serve(b"\xff\xfe\x00 not text")
    source._RETRIES = 0
    monkeypatch.setenv(FEED_ENV, FEED + "?v=2")
    binary = auscert_url_feed_status()
    assert binary["data"]["entries"] == 0
    assert any("not usable" in item for item in binary["warnings"])


# Auth, rate limit and timeout.


def test_401_and_403_name_the_env_vars(monkeypatch):
    _arm(monkeypatch)
    for status in (401, 403):
        monkeypatch.setenv(FEED_ENV, f"{FEED}?status={status}")
        _serve("denied", status=status)
        result = auscert_url_feed_lookup("example.com")
        assert result["data"] is None
        assert TOKEN_ENV in result["warnings"][0]
        assert FEED_ENV in result["warnings"][0]
        assert str(status) in result["warnings"][0]
        assert TOKEN not in json.dumps(result)


def test_429_honours_retry_after(monkeypatch):
    _arm(monkeypatch)
    sleeps: list[float] = []
    source._SLEEP = sleeps.append
    calls = {"n": 0}
    body = _fixture("url_feed_synthetic.txt").encode()

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "7"})
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(handler)
    found = auscert_url_feed_lookup(LISTED)
    assert found["data"]["listed"] is True
    assert 7.0 in sleeps

    source._RETRIES = 0
    monkeypatch.setenv(FEED_ENV, FEED + "?held=1")
    _serve("slow down", status=429, headers={"retry-after": "120"})
    held = auscert_url_feed_lookup(LISTED)
    assert held["data"] is None
    assert "Retry after 120 seconds" in held["warnings"][0]


def test_timeout_falls_back_to_cache(monkeypatch, tmp_path):
    _arm(monkeypatch)
    _serve(_fixture("url_feed_synthetic.txt"))
    assert auscert_url_feed_lookup(LISTED)["cache"] == "miss"
    with sqlite3.connect(tmp_path / "data" / "http_cache.sqlite") as conn:
        conn.execute("UPDATE http_cache SET fetched_at = ?", (time.time() - 2 * 3600,))

    def timeout(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    source._TRANSPORT = httpx.MockTransport(timeout)
    stale = auscert_url_feed_lookup(LISTED)
    assert stale["cache"] == "stale"
    assert stale["data"]["listed"] is True

    other = tmp_path / "empty"
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(other))
    gone = auscert_url_feed_lookup(LISTED)
    assert gone["data"] is None
    assert any("is unavailable" in item for item in gone["warnings"])


# Schema drift.


def test_schema_drift_fails_the_health_check(monkeypatch):
    assert schema_drift(_fixture("url_feed_synthetic.txt")) is None
    assert schema_drift(_fixture("url_feed_synthetic.csv")) is None
    assert "missing url column" in schema_drift(_fixture("url_feed_drift.csv"))
    assert connector().health(live=False, check_schema=True).ok is True
    monkeypatch.setenv(SNAPSHOT_ENV, str(FIXTURES / "url_feed_drift.csv"))
    failed = connector().health(live=False, check_schema=True)
    assert failed.ok is False
    assert "url column" in failed.detail
    from cyberau_common.cli import main

    assert main(["health", "auscert-member", "--schema-drift"]) != 0
    monkeypatch.delenv(SNAPSHOT_ENV)
    assert main(["health", "auscert-member", "--schema-drift"]) == 0


# Egress.


def test_redirect_to_another_host_is_refused(monkeypatch):
    _arm(monkeypatch)
    seen: list[httpx.Request] = []

    def redirect(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"location": "https://evil.example.net/steal"})

    source._TRANSPORT = httpx.MockTransport(redirect)
    refused = auscert_url_feed_lookup(LISTED)
    assert refused["data"] is None
    assert any("not allowlisted" in item for item in refused["warnings"])
    assert {request.url.host for request in seen} == {"feeds.example.com"}
    assert TOKEN not in json.dumps(refused)


def test_feed_url_must_be_https_with_a_host(monkeypatch):
    for bad, word in (
        ("http://feeds.example.com/x", "https"),
        ("https://user:pass@feeds.example.com/x", "userinfo"),
        ("https://203.0.113.10/feed", "IP literals"),
        ("https://feeds.example.com:abc/x", "not a valid URL"),
    ):
        monkeypatch.setenv(FEED_ENV, bad)
        result = auscert_url_feed_lookup("example.com")
        assert word in result["warnings"][0], bad
        assert "pass" not in json.dumps(result)


def test_static_allowlist_has_no_hosts():
    allow = yaml.safe_load((MCP / "egress-allowlist.yaml").read_text(encoding="utf-8"))
    assert allow["connectors"]["auscert-member"]["hosts"] == []


# Untrusted text.


def test_free_text_fields_are_wrapped_as_untrusted(monkeypatch):
    _arm(monkeypatch)
    _serve(_fixture("url_feed_synthetic.csv"))
    found = auscert_url_feed_lookup("mygov-refund.example.org")
    match = found["data"]["matches"][0]
    for field in ("url", "category", "first_seen"):
        assert match[field].startswith("<<untrusted source=auscert-member>>"), field
    assert "Ignore previous instructions" in match["category"]
    assert found["data"]["query"].startswith("<<untrusted source=auscert-member>>")


# Default state.


def test_unset_feed_names_the_env_var():
    result = auscert_url_feed_lookup("example.com")
    assert result["data"] is None
    assert FEED_ENV in result["warnings"][0]
    status = auscert_url_feed_status()
    assert status["data"]["configured"] is False
    assert connector().health(live=True).ok is False


def test_default_stays_off_and_terms_come_first():
    spec = yaml.safe_load((MCP / "servers.yaml").read_text(encoding="utf-8"))["servers"]["auscertm"]
    assert spec["connector"] == "auscert-member"
    assert spec["default_enabled"] is False
    assert spec["enabled_by_default"] is False
    assert spec["off_reason"] == "licence terms"
    assert spec["env"] == [
        "AUSCERT_URL_FEED=${AUSCERT_URL_FEED}",
        "AUSCERT_FEED_TOKEN=${AUSCERT_FEED_TOKEN}",
    ]
    assert DOCTOR_NOTE.startswith("off by default: licence terms")
    docs = (REPO / "docs" / "connectors" / "auscert-member.md").read_text(encoding="utf-8")
    skill = (REPO / "skills" / "auscert-url-feed" / "SKILL.md").read_text(encoding="utf-8")
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert TERMS in docs
    assert "off: licence terms" in docs
    assert skill.index(TERMS) < skill.index("auscert_url_feed_lookup")
    assert "docs/connectors/auscert-member.md" in readme
    for text in (docs, skill, (PACKAGE / "SOURCE.md").read_text(encoding="utf-8")):
        assert "\u2014" not in text


def _render(home: Path, env_text: str) -> dict:
    env_file = home / ".env"
    env_file.parent.mkdir(parents=True, exist_ok=True)
    env_file.write_text(env_text, encoding="utf-8")
    proc = subprocess.run(
        [
            sys.executable,
            str(REPO / "install" / "render_config.py"),
            "--profile-home",
            str(home),
            "--servers",
            str(MCP / "servers.yaml"),
            "--config",
            str(home / "config.yaml"),
            "--env-file",
            str(env_file),
            "--managed",
            str(home / "plugin-data" / "cyber-au" / "managed-servers.json"),
            "--status",
            str(home / "plugin-data" / "cyber-au" / "bootstrap-status.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    text = (home / "config.yaml").read_text(encoding="utf-8")
    assert TOKEN not in text
    return yaml.safe_load(text)["mcp_servers"]["auscertm"]


def test_fresh_install_with_the_key_renders_disabled_and_update_keeps_user_choice(tmp_path):
    home = tmp_path / "profile"
    env = f"{FEED_ENV}={FEED}\n{TOKEN_ENV}={TOKEN}\n"
    entry = _render(home, env)
    assert entry["enabled"] is False
    assert entry["env"][FEED_ENV] == "${AUSCERT_URL_FEED}"
    assert entry["env"][TOKEN_ENV] == "${AUSCERT_FEED_TOKEN}"
    assert entry["args"] == ["serve", "auscert-member"]
    config = home / "config.yaml"
    text = config.read_text(encoding="utf-8")
    block = text[text.index("  auscertm:") :]
    switched = block.replace("enabled: false", "enabled: true", 1)
    config.write_text(text.replace(block, switched), encoding="utf-8")
    assert _render(home, env)["enabled"] is True, "an update must keep the user's enabled: true"


# Secrets.


def test_no_secret_in_any_fixture_log_or_envelope(monkeypatch, tmp_path):
    for path in FIXTURES.iterdir():
        text = path.read_text(encoding="utf-8")
        assert TOKEN not in text
        for line in text.splitlines():
            if line.strip().lower().startswith("authorization"):
                assert "[REDACTED]" in line or line.strip().endswith(":")
        assert not re.search(r"(?i)bearer\s+(?!\[REDACTED\])\S{8,}", text)
    _arm(monkeypatch)
    monkeypatch.setenv("CYBERAU_AUDIT_LOG_PATH", str(tmp_path / "audit"))
    _serve(_fixture("url_feed_synthetic.txt"))
    results = [auscert_url_feed_lookup(LISTED), auscert_url_feed_status()]

    def leaks(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"authorization: Bearer {TOKEN}")

    monkeypatch.setenv(FEED_ENV, FEED + "?fresh=1")
    source._TRANSPORT = httpx.MockTransport(leaks)
    source._RETRIES = 0
    results.append(auscert_url_feed_lookup(LISTED))
    for result in results:
        assert TOKEN not in json.dumps(result)
    for path in (tmp_path / "data").rglob("*"):
        if path.is_file():
            assert TOKEN.encode() not in path.read_bytes(), path.name


def test_matches_persist_owner_only_in_the_profile(monkeypatch, tmp_path):
    _arm(monkeypatch)
    _serve(_fixture("url_feed_synthetic.txt"))
    auscert_url_feed_lookup(LISTED)
    stored = tmp_path / "data" / "auscert-member.sqlite"
    assert stored.stat().st_mode & 0o077 == 0
    with sqlite3.connect(stored) as conn:
        assert [row[0] for row in conn.execute("SELECT url FROM matches")] == [LISTED]


# Offline and snapshot.


def test_offline_uses_cache_then_reports_unavailable(monkeypatch, tmp_path):
    _arm(monkeypatch)
    _serve(_fixture("url_feed_synthetic.txt"))
    auscert_url_feed_lookup(LISTED)
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")

    def fail(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("offline must not use the network")

    source._TRANSPORT = httpx.MockTransport(fail)
    cached = auscert_url_feed_lookup(LISTED)
    assert cached["cache"] in {"hit", "stale"}
    assert cached["data"]["listed"] is True
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "empty"))
    gone = auscert_url_feed_lookup(LISTED)
    assert gone["cache"] == "snapshot"
    assert gone["data"] is None
    assert any("is unavailable" in item for item in gone["warnings"])


def test_operator_snapshot_is_labelled(monkeypatch):
    monkeypatch.setenv(SNAPSHOT_ENV, str(FIXTURES / "url_feed_synthetic.txt"))
    found = auscert_url_feed_lookup(LISTED)
    assert found["cache"] == "snapshot"
    assert found["warnings"][0] == OPERATOR_NOTE
    assert found["data"]["listed"] is True


def test_parse_feed_skips_comments_and_dedupes():
    entries, fmt, problem = parse_feed(_fixture("url_feed_synthetic.txt"))
    assert (fmt, problem) == ("text", "")
    assert [item["url"] for item in entries] == [
        LISTED,
        "http://parcel-tracking.example.net/au/redelivery?id=00001",
        "https://mygov-refund.example.org/claim",
        "https://cdn.example.net/payload.js",
    ]


def test_live_health_with_a_key(monkeypatch):
    _arm(monkeypatch)
    _serve(_fixture("url_feed_synthetic.txt"))
    probe = connector().health(live=True)
    assert probe.ok is True, probe.detail
    assert "4 entries" in probe.detail


def test_cassettes_replay_with_redacted_auth():
    import vcr

    player = vcr.VCR(record_mode="none")
    for tool in TOOLS:
        path = FIXTURES / f"{tool}.yaml"
        text = path.read_text(encoding="utf-8")
        assert "[REDACTED]" in text
        assert TOKEN not in text
        with player.use_cassette(str(path)):
            played = httpx.get(FEED)
        assert played.status_code == 200
        entries, _fmt, problem = parse_feed(played.text)
        assert problem == "" and len(entries) == 4


def test_attribution_states_the_terms():
    assert TERMS in ATTRIBUTION
