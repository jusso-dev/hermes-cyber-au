"""SpyCloud connector tests. Fixtures are synthetic. No licence key is embedded."""

import ipaddress
import json
import re
from datetime import date
from pathlib import Path

import httpx
import pytest
import yaml
from cyberau_common.cli import main
from cyberau_common.server import build_server
from cyberau_premium.base import Watchlist
from cyberau_premium.budget import BudgetLedger
from cyberau_premium.catalog import get_vendor
from cyberau_premium.samples import SCHEMA
from cyberau_premium.status import format_premium_doctor, load_servers, render_premium_servers
from cyberau_spycloud import source
from cyberau_spycloud.source import (
    WATCHLIST_URL,
    compare_watchlists,
    connector,
    doctor_report,
    schema_drift,
    spycloud_breach_info,
    spycloud_watchlist_exposure,
    watchlist_doctor,
)
from jsonschema import Draft202012Validator

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ROOT = Path(__file__).resolve().parents[3]
ENVELOPE = {
    "type": "object",
    "required": ["source", "retrieved_at", "cache", "data", "untrusted", "attribution"],
    "properties": {
        "source": {"type": "string"},
        "cache": {"enum": ["hit", "miss", "stale", "snapshot"]},
        "attribution": {"type": "string"},
        "untrusted": {"const": True},
        "warnings": {"type": "array", "items": {"type": "string"}},
        "data": {},
        "retrieved_at": {"type": "string"},
        "source_urls": {"type": "array"},
        "data_as_of": {},
    },
}
FINDING = Draft202012Validator(SCHEMA, format_checker=Draft202012Validator.FORMAT_CHECKER)
SECRET_HEADER = re.compile(
    r"(?i)(authorization|auth-key|x-otx-api-key|x-api-key|api-key)\s*:\s*(?!\[REDACTED\]|\s*$)\S+"
)
EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b")
KEY = "test-key-not-real"
TERMS = (
    "Commercial licence. Session cache for records. Store metadata only. "
    "No STIX export. Prefer hashed values when the licence allows."
)


def _resolve(_host: str):
    return [ipaddress.ip_address("1.1.1.1")]


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    for name in (
        "SPYCLOUD_API_KEY",
        "CYBERAU_OFFLINE",
        "CYBERAU_SPYCLOUD_WATCHLIST_SNAPSHOT",
        "CYBERAU_SPYCLOUD_CATALOG_SNAPSHOT",
        "CYBERAU_SPYCLOUD_IDENTIFIERS_SNAPSHOT",
        "CYBERAU_ORG_WATCHLIST",
        "CYBERAU_EGRESS_ALLOWLIST",
    ):
        monkeypatch.delenv(name, raising=False)
    source.reset_runtime()
    yield
    source.reset_runtime()


def _snapshot(monkeypatch, name: str = "watchlist"):
    if name == "watchlist":
        monkeypatch.setenv(
            "CYBERAU_SPYCLOUD_WATCHLIST_SNAPSHOT",
            str(FIXTURES / "watchlist_synthetic.json"),
        )
    else:
        monkeypatch.setenv(
            "CYBERAU_SPYCLOUD_CATALOG_SNAPSHOT",
            str(FIXTURES / "breach_catalog_synthetic.json"),
        )


def _watchlist(tmp_path, monkeypatch, body: str | None = None) -> Path:
    path = tmp_path / "org-exposure.yaml"
    path.write_text(
        body
        or """
organisation: Example Pty Ltd
domains:
  - example.com.au
email_domains:
  - example.com.au
exclude: []
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_ORG_WATCHLIST", str(path))
    return path


def _live(monkeypatch, handler):
    monkeypatch.setenv("SPYCLOUD_API_KEY", KEY)
    source._RESOLVER = _resolve
    source._RNG = lambda: 0
    source._TRANSPORT = httpx.MockTransport(handler)


def test_happy_path_validates_schemas(monkeypatch, tmp_path):
    _snapshot(monkeypatch)
    _snapshot(monkeypatch, "catalog")
    _watchlist(tmp_path, monkeypatch)
    found = spycloud_watchlist_exposure(since="2026-06-01", watchlist_type="domain", limit=10)
    Draft202012Validator(ENVELOPE).validate(found)
    assert found["cache"] == "snapshot"
    assert found["attribution"] == TERMS
    assert found["warnings"] == []
    assert found["data"]["summary"] == {
        "by_type": {"infected": 1, "corporate": 1},
        "by_severity": {"20": 1, "5": 1},
    }
    records = found["data"]["records"]
    assert len(records) == 2
    assert records[0]["kind"] == "infostealer_credential"
    assert records[1]["kind"] == "breach_credential"
    for record in records:
        FINDING.validate(record)
        assert record["subject"]["value"].startswith("<<untrusted source=spycloud>>")
        assert "<<end untrusted>>" in record["subject"]["value"]
    blob = json.dumps(found)
    assert "synthetic-password" not in blob
    assert "ada@example.com.au" not in blob
    assert "bob@example.com.au" not in blob
    assert "https://example.com.au/login" not in blob
    store = (tmp_path / "intel.sqlite").read_bytes()
    assert b"synthetic-password" not in store
    assert b"ada@example.com.au" not in store
    assert b"example.com.au" in store

    breach = spycloud_breach_info("4242")
    Draft202012Validator(ENVELOPE).validate(breach)
    assert breach["attribution"] == TERMS
    assert breach["data"]["record_count"] == 2
    assert breach["data"]["publish_date"] == "2026-05-01T00:00:00Z"
    assert breach["data"]["title"].startswith("<<untrusted source=spycloud>>")
    assert "Example catalogue entry" in breach["data"]["title"]
    assert any("password" in item for item in breach["data"]["data_classes"])
    assert "synthetic-password" not in json.dumps(breach)


def test_filters_empty_and_malformed(monkeypatch, tmp_path):
    _snapshot(monkeypatch)
    infected = spycloud_watchlist_exposure(type="infected")
    assert len(infected["data"]["records"]) == 1
    assert infected["data"]["summary"]["by_type"] == {"infected": 1}
    later = spycloud_watchlist_exposure(since="2026-06-03", limit=1)
    assert len(later["data"]["records"]) == 1
    assert later["data"]["records"][0]["kind"] == "breach_credential"
    assert spycloud_watchlist_exposure(since="2099-01-01")["data"]["records"] == []
    assert spycloud_watchlist_exposure(limit=0)["warnings"]
    assert spycloud_watchlist_exposure(since="06-01-2026")["warnings"]

    empty = tmp_path / "empty.json"
    empty.write_text('{"cursor": "", "hits": 0, "results": []}', encoding="utf-8")
    monkeypatch.setenv("CYBERAU_SPYCLOUD_WATCHLIST_SNAPSHOT", str(empty))
    quiet = spycloud_watchlist_exposure()
    assert quiet["data"]["records"] == []
    assert quiet["warnings"] == []

    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    monkeypatch.setenv("CYBERAU_SPYCLOUD_WATCHLIST_SNAPSHOT", str(bad))
    warned = spycloud_watchlist_exposure()
    assert warned["data"] is None
    assert warned["warnings"]
    assert "usable" in warned["warnings"][0]


def test_auth_errors_name_the_env_var(monkeypatch):
    body = (FIXTURES / "spycloud_403.json").read_bytes()

    def forbidden(_request):
        return httpx.Response(403, content=body)

    _live(monkeypatch, forbidden)
    refused = spycloud_watchlist_exposure()
    assert refused["data"] is None
    assert "SPYCLOUD_API_KEY" in refused["warnings"][0]
    assert "403" in refused["warnings"][0]
    assert KEY not in json.dumps(refused)

    def unauthorized(_request):
        return httpx.Response(401, content=body)

    source._TRANSPORT = httpx.MockTransport(unauthorized)
    denied = spycloud_breach_info("4242")
    assert "SPYCLOUD_API_KEY" in denied["warnings"][0]
    assert "401" in denied["warnings"][0]
    assert KEY not in json.dumps(denied)

    missing = spycloud_watchlist_exposure()
    source.reset_runtime()
    monkeypatch.delenv("SPYCLOUD_API_KEY")
    missing = spycloud_watchlist_exposure()
    assert "SPYCLOUD_API_KEY" in missing["warnings"][0]
    with pytest.raises(RuntimeError, match="SPYCLOUD_API_KEY"):
        connector().exposure_for(Watchlist(domains=["example.com.au"]), date(2026, 6, 1))


def test_retry_after_and_timeout_cache(monkeypatch, tmp_path):
    delays = []
    source._SLEEPER = delays.append
    watch = (FIXTURES / "watchlist_synthetic.json").read_bytes()
    limited = (FIXTURES / "spycloud_429.json").read_bytes()
    calls = {"n": 0}

    def limited_then_ok(_request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "2"}, content=limited)
        return httpx.Response(200, content=watch)

    _live(monkeypatch, limited_then_ok)
    source._SLEEPER = delays.append
    found = spycloud_watchlist_exposure()
    assert calls["n"] == 2
    assert 2.0 in delays
    assert found["data"]["records"]
    assert KEY not in json.dumps(found)
    assert not (tmp_path / "spycloud-session.sqlite").exists()

    cache = source._session_cache()
    for item in cache._memory.values():
        item.fetched_at -= 4000

    def time_out(_request):
        calls["n"] += 1
        raise httpx.TimeoutException("timed out")

    source._TRANSPORT = httpx.MockTransport(time_out)
    stale = spycloud_watchlist_exposure()
    assert stale["cache"] == "stale"
    assert stale["data"]["records"]
    assert "synthetic-password" not in json.dumps(stale)


def test_offline_snapshot_or_unavailable(monkeypatch):
    _snapshot(monkeypatch)
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.delenv("CYBERAU_SPYCLOUD_WATCHLIST_SNAPSHOT")
    missing = spycloud_watchlist_exposure()
    assert missing["cache"] == "snapshot"
    assert any("unavailable" in item for item in missing["warnings"])


def test_redirect_outside_the_allowlist_is_refused(monkeypatch):
    seen = []

    def redirect(request: httpx.Request):
        seen.append(request.url.host)
        return httpx.Response(302, headers={"Location": "https://evil.example/collect"})

    _live(monkeypatch, redirect)
    refused = spycloud_watchlist_exposure()
    assert seen == ["api.spycloud.io"]
    assert refused["data"] is None
    assert "not allowlisted" in refused["warnings"][0]
    assert "evil.example" in refused["warnings"][0]
    assert WATCHLIST_URL.startswith("https://api.spycloud.io/")


def test_schema_drift_fails_health(monkeypatch, tmp_path, capsys):
    assert connector().health(live=False, check_schema=True).ok is True
    assert main(["health", "spycloud", "--schema-drift"]) == 0
    assert "ok" in capsys.readouterr().out
    renamed = tmp_path / "renamed.json"
    renamed.write_text(
        json.dumps(
            {
                "hits": 1,
                "results": [
                    {
                        "doc_id": "doc-example-1",
                        "source_id": 1,
                        "spycloud_publish_date": "2026-06-02T01:00:00Z",
                        "severity": 2,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_SPYCLOUD_WATCHLIST_SNAPSHOT", str(renamed))
    probe = connector().health(live=False, check_schema=True)
    assert probe.ok is False
    assert "schema drift" in probe.detail
    assert "document_id" in probe.detail
    assert schema_drift(json.loads(renamed.read_text(encoding="utf-8")), kind="watchlist")
    assert main(["health", "spycloud", "--schema-drift"]) == 1


def test_catalogue_metadata_is_cached_for_a_day(monkeypatch, tmp_path):
    calls = {"n": 0}
    body = (FIXTURES / "breach_catalog_synthetic.json").read_bytes()

    def handler(request: httpx.Request):
        calls["n"] += 1
        assert request.headers["x-api-key"] == KEY
        assert str(request.url).endswith("/breach/catalog/4242")
        return httpx.Response(200, content=body)

    _live(monkeypatch, handler)
    first = spycloud_breach_info("4242")
    second = spycloud_breach_info("4242")
    assert calls["n"] == 1
    assert first["cache"] == "miss"
    assert second["cache"] == "hit"
    assert (tmp_path / "spycloud-catalog.sqlite").exists()
    assert b"synthetic-password" not in (tmp_path / "spycloud-catalog.sqlite").read_bytes()
    assert KEY.encode() not in (tmp_path / "spycloud-catalog.sqlite").read_bytes()


def test_pages_stop_at_the_vendor_ceiling(monkeypatch):
    calls = {"n": 0}

    def handler(_request):
        calls["n"] += 1
        return httpx.Response(
            200,
            json={
                "cursor": "again",
                "hits": 1,
                "results": [
                    {
                        "document_id": f"doc-{calls['n']}",
                        "source_id": 1,
                        "spycloud_publish_date": "2026-06-02T01:00:00Z",
                        "severity": 2,
                        "domain": "example.com.au",
                    }
                ],
            },
        )

    _live(monkeypatch, handler)
    found = spycloud_watchlist_exposure(limit=1000)
    assert calls["n"] == get_vendor("spycloud").max_pages
    assert len(found["data"]["records"]) == get_vendor("spycloud").max_pages


def test_exposure_for_keeps_watchlist_subjects(monkeypatch, tmp_path):
    payload = {
        "cursor": "",
        "hits": 2,
        "results": [
            {
                "document_id": "doc-example-1",
                "source_id": 1,
                "spycloud_publish_date": "2026-06-02T01:00:00Z",
                "severity": 3,
                "domain": "example.com.au",
                "password": "synthetic-password",
            },
            {
                "document_id": "doc-other-1",
                "source_id": 1,
                "spycloud_publish_date": "2026-06-02T01:00:00Z",
                "severity": 3,
                "domain": "other.example.au",
            },
        ],
    }
    path = tmp_path / "both.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("CYBERAU_SPYCLOUD_WATCHLIST_SNAPSHOT", str(path))
    _watchlist(tmp_path, monkeypatch)
    findings = connector().exposure_for(Watchlist(domains=["example.com.au"]), date(2026, 6, 1))
    assert [item.subject.value for item in findings] == ["example.com.au"]
    stored = (tmp_path / "intel.sqlite").read_bytes()
    assert b"other.example.au" not in stored
    assert b"synthetic-password" not in stored


def test_doctor_compares_watchlists(monkeypatch, tmp_path):
    local = tmp_path / "org-exposure.yaml"
    local.write_text(
        """
organisation: Example Pty Ltd
abns:
  - "51 824 753 556"
domains:
  - example.com.au
  - example.au
email_domains:
  - example.com.au
brands:
  - Example
subsidiaries:
  - name: Example Services Pty Ltd
    domains: [services.example.com.au]
exclude:
  - example.com
alert:
  min_confidence: vendor_reported
""",
        encoding="utf-8",
    )
    remote = tmp_path / "identifiers.json"
    remote.write_text(
        json.dumps(
            {
                "cursor": "",
                "hits": 4,
                "results": [
                    {
                        "identifier_name": "example.com.au",
                        "identifier_type": "domain",
                        "status": "ACTIVE",
                    },
                    {
                        "identifier_name": "ada@example.com.au",
                        "identifier_type": "email",
                        "status": "ACTIVE",
                    },
                    {
                        "identifier_name": "other.example.au",
                        "identifier_type": "domain",
                        "status": "ACTIVE",
                    },
                    {
                        "identifier_name": "203.0.113.10",
                        "identifier_type": "ip",
                        "status": "ACTIVE",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_ORG_WATCHLIST", str(local))
    monkeypatch.setenv("CYBERAU_SPYCLOUD_IDENTIFIERS_SNAPSHOT", str(remote))
    report = watchlist_doctor(enabled=False)
    assert report.startswith("off by default: licence terms (docs/connectors/spycloud.md)")
    assert "missing from SpyCloud: example.au, services.example.com.au" in report
    assert "missing from local watchlist: other.example.au" in report
    loaded = yaml.safe_load(local.read_text(encoding="utf-8"))
    remote_rows = json.loads(remote.read_text(encoding="utf-8"))["results"]
    gaps = compare_watchlists(Watchlist.model_validate(loaded), remote_rows)
    assert "example.com" not in gaps["missing_from_spycloud"]
    assert doctor_report(enabled=False, key_present=True).startswith("off by default")


def test_default_state_and_registration(tmp_path):
    servers = load_servers()
    entry = servers["spycloud"]
    assert entry["default_enabled"] is False
    assert entry["enabled_by_default"] is False
    assert entry["connector"] == "spycloud"
    env = {"SPYCLOUD_API_KEY": "present"}
    rendered = render_premium_servers(servers, env=env)
    assert rendered["spycloud"]["enabled"] is False
    assert "present" not in json.dumps(rendered["spycloud"])
    kept = render_premium_servers(servers, env=env, user_enabled={"spycloud": True})
    assert kept["spycloud"]["enabled"] is True
    allow = yaml.safe_load((ROOT / "mcp" / "egress-allowlist.yaml").read_text(encoding="utf-8"))
    assert allow["connectors"]["spycloud"]["hosts"] == ["api.spycloud.io"]
    ledger = BudgetLedger(tmp_path / "premium-ledger.sqlite")
    doctor = format_premium_doctor({"SPYCLOUD_API_KEY": "present"}, {}, ledger)
    assert "spycloud: off (paid, bring your own licence)" in doctor
    docs = (ROOT / "docs" / "connectors" / "spycloud.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/connectors/spycloud.md" in readme
    assert TERMS in docs
    assert "off by default: licence terms" in docs
    assert "\u2014" not in docs
    assert "\u2013" not in docs
    assert connector().health(live=True).detail == "not configured"


def test_tools_are_read_only_and_fixtures_are_clean():
    listed = __import__("asyncio").run(build_server(connector()).list_tools())
    tools = {tool.name: tool for tool in listed}
    assert len("mcp__spycloud__spycloud_watchlist_exposure") == 42
    assert len("mcp__spycloud__spycloud_breach_info") == 35
    for name, tool in tools.items():
        assert tool.annotations.readOnlyHint is True
        assert tool.annotations.openWorldHint is True
        schema_path = ROOT / "mcp" / "spycloud" / "schema" / f"{name}.input.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
    allowed = {"example.com", "example.com.au", "example.au"}
    for path in FIXTURES.iterdir():
        text = path.read_text(encoding="utf-8")
        assert not SECRET_HEADER.search(text)
        assert KEY not in text
        for match in EMAIL.finditer(text):
            assert match.group(1).lower() in allowed


def test_vcr_filters_the_api_key_header(vcr_config):
    assert "x-api-key" in vcr_config["filter_headers"]
