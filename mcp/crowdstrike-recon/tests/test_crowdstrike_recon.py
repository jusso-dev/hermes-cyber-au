"""CrowdStrike Recon connector tests. Fixtures are synthetic. No live licence."""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from datetime import date
from pathlib import Path

import cyberau_crowdstrike_recon.source as source
import httpx
import jsonschema
from cyberau_common.server import build_server
from cyberau_crowdstrike_recon.source import (
    connector,
    cs_recon_notifications,
    cs_recon_rules,
    render_connector_doc,
    schema_drift,
)
from cyberau_premium.base import PremiumConnector, Watchlist
from cyberau_premium.caching import clear_session_caches
from cyberau_premium.status import load_servers, render_premium_servers
from falconpy import Recon

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ROOT = Path(__file__).resolve().parents[3]
NOTIFICATIONS = json.loads((FIXTURES / "notifications_synthetic.json").read_text())
RULES = json.loads((FIXTURES / "rules_synthetic.json").read_text())
OAUTH_401 = json.loads((FIXTURES / "oauth_401.json").read_text())
SECRET = "fixture-client-secret"
CLIENT = "fixture-client-id"
TOKEN = "fixture-access-token"


def _resolver(_host: str):
    return [ipaddress.ip_address("1.1.1.1")]


def setup_function():
    source._TRANSPORT = None
    source._SLEEPER = None
    source._RESOLVER = _resolver
    source._CACHE = None
    clear_session_caches()


def teardown_function():
    source._TRANSPORT = None
    source._SLEEPER = None
    source._RESOLVER = None
    source._CACHE = None
    clear_session_caches()


def _keys(monkeypatch):
    monkeypatch.setenv("FALCON_CLIENT_ID", CLIENT)
    monkeypatch.setenv("FALCON_CLIENT_SECRET", SECRET)
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.delenv("FALCON_BASE_URL", raising=False)
    monkeypatch.delenv("CYBERAU_CSRECON_SNAPSHOT", raising=False)
    monkeypatch.delenv("CYBERAU_CSRECON_RULES_SNAPSHOT", raising=False)


def _operator_snapshots(monkeypatch):
    monkeypatch.setenv("CYBERAU_CSRECON_SNAPSHOT", str(FIXTURES / "notifications_synthetic.json"))
    monkeypatch.setenv("CYBERAU_CSRECON_RULES_SNAPSHOT", str(FIXTURES / "rules_synthetic.json"))


def _transport(handler):
    source._TRANSPORT = httpx.MockTransport(handler)


def _ok_handler(urls: list[str], *, query_status=None):
    hits = {"notifications": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        path = request.url.path
        if path.endswith("/oauth2/token"):
            return httpx.Response(
                201,
                json={
                    "access_token": TOKEN,
                    "expires_in": 1799,
                    "token_type": "bearer",
                },
            )
        if path.endswith("/recon/queries/notifications/v1"):
            hits["notifications"] += 1
            status = query_status(hits["notifications"]) if query_status else 200
            if status == 429:
                return httpx.Response(
                    429,
                    headers={"Retry-After": "2"},
                    json={"errors": [{"code": 429, "message": "rate limited"}]},
                )
            if status >= 400:
                return httpx.Response(
                    status,
                    json={"errors": [{"code": status, "message": "denied"}]},
                )
            ids = [item["id"] for item in NOTIFICATIONS["resources"]]
            return httpx.Response(200, json={"resources": ids, "errors": []})
        if path.endswith("/recon/entities/notifications/v1"):
            return httpx.Response(200, json=NOTIFICATIONS)
        if path.endswith("/recon/queries/rules/v1"):
            ids = [item["id"] for item in RULES["resources"]]
            return httpx.Response(200, json={"resources": ids, "errors": []})
        if path.endswith("/recon/entities/rules/v1"):
            return httpx.Response(200, json=RULES)
        return httpx.Response(404, json={"errors": [{"message": "not stubbed"}]})

    return handler


def _validate(name: str, payload: dict):
    schema = json.loads((ROOT / "mcp" / "crowdstrike-recon" / "schema" / name).read_text())
    jsonschema.Draft202012Validator(schema).validate(payload)


def test_happy_path_uses_falconpy_and_wraps_text(tmp_path, monkeypatch):
    _keys(monkeypatch)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    urls: list[str] = []
    calls: list[str] = []

    class Recording(Recon):
        def query_notifications(self, *args, **kwargs):
            calls.append("query_notifications")
            return super().query_notifications(*args, **kwargs)

        def get_notifications(self, *args, **kwargs):
            calls.append("get_notifications")
            return super().get_notifications(*args, **kwargs)

        def query_rules(self, *args, **kwargs):
            calls.append("query_rules")
            return super().query_rules(*args, **kwargs)

        def get_rules(self, *args, **kwargs):
            calls.append("get_rules")
            return super().get_rules(*args, **kwargs)

    monkeypatch.setattr(source, "Recon", Recording)
    _transport(_ok_handler(urls))
    found = cs_recon_notifications(since="2026-06-01", limit=100)
    _validate("cs_recon_notifications.response.json", found)
    assert found["cache"] == "miss"
    assert found["attribution"].startswith("Commercial licence")
    assert found["data"][0]["id"] == "notif-example-1"
    assert "<<untrusted source=csrecon>>" in found["data"][0]["rule_name"]
    assert "<<untrusted source=csrecon>>" in found["data"][0]["match_summary"]
    assert TOKEN not in json.dumps(found)
    assert SECRET not in json.dumps(found)
    rules = cs_recon_rules()
    _validate("cs_recon_rules.response.json", rules)
    assert rules["data"][0]["topic"] == "SA"
    assert "<<untrusted source=csrecon>>" in rules["data"][0]["name"]
    assert "<<untrusted source=csrecon>>" in rules["data"][0]["filter"]
    assert calls == [
        "query_notifications",
        "get_notifications",
        "query_rules",
        "get_rules",
    ]
    assert any("/recon/queries/notifications/v1" in url for url in urls)
    assert any("/recon/entities/rules/v1" in url for url in urls)
    again = cs_recon_notifications(since="2026-06-01", limit=100)
    assert again["cache"] == "hit"
    rows = sqlite3.connect(tmp_path / "rate_limit.sqlite").execute("select count(*) from rolling")
    assert rows.fetchone()[0] >= 3


def test_since_filters_sydney_day_and_limit(tmp_path, monkeypatch):
    _keys(monkeypatch)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    _transport(_ok_handler([]))
    june = cs_recon_notifications(since="2026-06-01", limit=100)
    assert [row["id"] for row in june["data"]] == ["notif-example-1"]
    older = cs_recon_notifications(since="2026-06-02", limit=100)
    assert older["data"] == []
    source._CACHE = None
    clear_session_caches()
    newest = cs_recon_notifications(limit=1)
    assert [row["id"] for row in newest["data"]] == ["notif-example-1"]
    assert cs_recon_notifications(since="16 October 2026")["warnings"]
    assert cs_recon_notifications(limit=0)["warnings"]


def test_empty_and_malformed_payloads(tmp_path, monkeypatch):
    _keys(monkeypatch)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))

    def empty(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/oauth2/token"):
            return httpx.Response(201, json={"access_token": TOKEN, "expires_in": 1799})
        return httpx.Response(200, json={"resources": [], "errors": []})

    _transport(empty)
    assert cs_recon_notifications()["data"] == []
    assert cs_recon_rules()["data"] == []
    source._CACHE = None
    clear_session_caches()

    def broken(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/oauth2/token"):
            return httpx.Response(201, json={"access_token": TOKEN, "expires_in": 1799})
        if request.url.path.endswith("/recon/queries/notifications/v1"):
            return httpx.Response(200, json={"resources": ["notif-example-1"]})
        return httpx.Response(200, json={"resources": {"renamed": True}})

    _transport(broken)
    warned = cs_recon_notifications()
    assert warned["data"] == []
    assert warned["warnings"]
    assert "not usable" in warned["warnings"][0]


def test_auth_errors_name_the_env_vars(tmp_path, monkeypatch):
    monkeypatch.delenv("FALCON_CLIENT_ID", raising=False)
    monkeypatch.delenv("FALCON_CLIENT_SECRET", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    missing = cs_recon_notifications()
    assert "FALCON_CLIENT_ID" in missing["warnings"][0]
    assert "FALCON_CLIENT_SECRET" in missing["warnings"][0]
    _keys(monkeypatch)
    monkeypatch.delenv("FALCON_CLIENT_SECRET", raising=False)
    secret = cs_recon_rules()
    assert secret["warnings"][0] == (
        "CrowdStrike Recon rules is unavailable: FALCON_CLIENT_SECRET is not set. "
        "No live, cached or shipped data was served"
    )

    def denied(status: int):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/oauth2/token") and status == 401:
                return httpx.Response(401, json=OAUTH_401)
            if request.url.path.endswith("/oauth2/token"):
                return httpx.Response(201, json={"access_token": TOKEN, "expires_in": 1799})
            return httpx.Response(
                status,
                json={"errors": [{"code": status, "message": "denied"}]},
            )

        return handler

    _keys(monkeypatch)
    _transport(denied(401))
    unauthorised = cs_recon_notifications()
    assert "401" in unauthorised["warnings"][0]
    assert "FALCON_CLIENT_ID" in unauthorised["warnings"][0]
    assert "FALCON_CLIENT_SECRET" in unauthorised["warnings"][0]
    assert SECRET not in json.dumps(unauthorised)
    source._CACHE = None
    clear_session_caches()
    _transport(denied(403))
    forbidden = cs_recon_rules()
    assert "403" in forbidden["warnings"][0]
    assert "FALCON_CLIENT_SECRET" in forbidden["warnings"][0]


def test_retry_after_is_honoured(tmp_path, monkeypatch):
    _keys(monkeypatch)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    delays: list[float] = []
    source._SLEEPER = delays.append
    _transport(_ok_handler([], query_status=lambda hit: 429 if hit == 1 else 200))
    found = cs_recon_notifications(limit=10)
    assert found["data"]
    assert delays == [2.0]
    assert found["warnings"] == []


def test_timeout_falls_back_to_cache(tmp_path, monkeypatch):
    _keys(monkeypatch)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    _transport(_ok_handler([]))
    first = cs_recon_notifications(limit=10)
    assert first["cache"] == "miss"
    item, _rows = source._recall("notifications", None, 10)
    assert item is not None
    item.ttl = 0

    def time_out(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    _transport(time_out)
    second = cs_recon_notifications(limit=10)
    assert second["cache"] == "stale"
    assert second["data"][0]["id"] == "notif-example-1"
    source._CACHE = None
    clear_session_caches()
    failed = cs_recon_notifications(limit=10)
    assert failed["data"] == []
    assert "timed out" in failed["warnings"][0]


def test_redirect_off_allowlist_is_refused(tmp_path, monkeypatch):
    _keys(monkeypatch)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    urls: list[str] = []

    def redirect(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        if request.url.path.endswith("/oauth2/token"):
            return httpx.Response(
                302,
                headers={"location": "https://not-allowlisted.example.com/oauth2/token"},
            )
        return httpx.Response(500, json={"errors": [{"message": "should not be called"}]})

    _transport(redirect)
    warned = cs_recon_notifications()
    assert warned["warnings"]
    assert "not allowlisted" in warned["warnings"][0]
    assert all("not-allowlisted.example.com" not in url for url in urls)


def test_schema_drift_and_offline_snapshot(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    _keys(monkeypatch)
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    _operator_snapshots(monkeypatch)
    offline = cs_recon_notifications(since="2026-06-01")
    assert offline["cache"] == "snapshot"
    assert offline["data"][0]["id"] == "notif-example-1"
    assert cs_recon_rules()["data"][0]["id"] == "rule-example-1"
    probe = connector().health(live=False, check_schema=True)
    assert probe.ok is True
    monkeypatch.delenv("CYBERAU_CSRECON_SNAPSHOT")
    fixture_probe = connector().health(live=False, check_schema=True)
    assert fixture_probe.ok is True
    drift = tmp_path / "drift.json"
    drift.write_text(
        json.dumps({"resources": [{"id": "notif-example-1", "rule_label": "renamed"}]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_CSRECON_SNAPSHOT", str(drift))
    failed = connector().health(live=False, check_schema=True)
    assert failed.ok is False
    assert "rule_name" in failed.detail
    assert schema_drift({"resources": []}) is None


def test_findings_match_watchlist_and_drop_secrets(tmp_path, monkeypatch):
    _keys(monkeypatch)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    watch = Watchlist(domains=["example.com.au"])
    body = json.loads(json.dumps(NOTIFICATIONS))
    body["resources"][0]["summary"] = "password=hunter2 cookie=sess-abc on example.com.au"
    body["resources"].append(
        {
            "id": "notif-other",
            "created_date": "2026-06-02T00:00:00Z",
            "rule_id": "rule-example-1",
            "rule_name": "Other",
            "rule_topic": "SA",
            "status": "new",
            "summary": "Synthetic mention of other.example.com.au",
            "typosquatting": {
                "base_domain": "other.example.com.au",
                "parent_domain": {"base_domain": "other.example.com.au"},
            },
        }
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/oauth2/token"):
            return httpx.Response(201, json={"access_token": TOKEN, "expires_in": 1799})
        if "queries" in request.url.path:
            ids = [item["id"] for item in body["resources"]]
            return httpx.Response(200, json={"resources": ids})
        return httpx.Response(200, json=body)

    _transport(handler)
    findings = connector().exposure_for(watch, date(2026, 6, 1))
    assert [item.source_ref for item in findings] == ["notif-example-1"]
    assert findings[0].kind == "dark_web_mention"
    assert findings[0].stix_exportable is False
    assert findings[0].licence_scope == "store_metadata"
    blob = (tmp_path / "intel.sqlite").read_bytes()
    assert b"hunter2" not in blob
    assert b"sess-abc" not in blob
    assert SECRET.encode() not in blob
    listed = cs_recon_notifications(since="2026-06-01", limit=100)
    rendered = json.dumps(listed)
    assert "hunter2" not in rendered
    assert "<<untrusted source=csrecon>>" in listed["data"][0]["match_summary"]


def test_default_state_stays_off_and_keeps_user_choice():
    env = {
        "FALCON_CLIENT_ID": "present",
        "FALCON_CLIENT_SECRET": "present",
        "FALCON_BASE_URL": "present",
    }
    fresh = render_premium_servers(load_servers(), env=env)
    assert fresh["csrecon"]["enabled"] is False
    assert "present" not in json.dumps(fresh["csrecon"])
    kept = render_premium_servers(load_servers(), env=env, user_enabled={"csrecon": True})
    assert kept["csrecon"]["enabled"] is True
    assert isinstance(connector(), PremiumConnector)
    assert connector().terms is not None
    assert connector().terms.cache == "session"
    assert connector().terms.stix_export is False


def test_live_health_is_one_rules_query(tmp_path, monkeypatch):
    _keys(monkeypatch)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    urls: list[str] = []
    _transport(_ok_handler(urls))
    probe = connector().health(live=True)
    assert probe.ok is True
    assert probe.detail == "live ok"
    recon = [url for url in urls if "/recon/" in url]
    assert len(recon) == 1
    assert "/recon/queries/rules/v1" in recon[0]
    assert "limit=1" in recon[0]
    assert "/entities/" not in recon[0]
    _transport(
        lambda request: (
            httpx.Response(401, json=OAUTH_401)
            if request.url.path.endswith("/oauth2/token")
            else httpx.Response(500, json={"errors": [{"message": "no"}]})
        )
    )
    failed = connector().health(live=True)
    assert failed.ok is False
    assert "FALCON_CLIENT_ID" in failed.detail


def test_read_only_session_rejects_rule_creation(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    policy = source._policy()
    session = source.GovernedSession(
        policy=policy,
        limiter=source._limiter(),
        transport=httpx.MockTransport(lambda request: httpx.Response(500)),
        sleeper=lambda _delay: None,
    )
    try:
        raised = False
        try:
            session.request(
                "POST",
                "https://api.crowdstrike.com/recon/entities/rules/v1",
                json={"name": "should-not-send"},
            )
        except PermissionError as exc:
            raised = True
            assert "read-only" in str(exc)
        assert raised is True
    finally:
        session.close()


def test_docs_fixtures_and_tool_contract():
    doc = ROOT / "docs" / "connectors" / "crowdstrike-recon.md"
    # The page is generated by tools/build_connector_docs.py from SOURCE.md. The
    # tool and terms tables there must still match the premium catalogue.
    page = doc.read_text(encoding="utf-8")
    table_rows = [line for line in render_connector_doc().splitlines() if line.startswith("| `")]
    assert table_rows
    for line in table_rows:
        assert line in page, line
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "[docs/connectors/crowdstrike-recon.md](docs/connectors/crowdstrike-recon.md)" in readme
    assert "\u2014" not in doc.read_text(encoding="utf-8")
    # Synthetic copies live only under tests/fixtures. Nothing ships in the package.
    assert not (Path(source.__file__).resolve().parent / "data").exists()
    for path in FIXTURES.iterdir():
        text = path.read_text(encoding="utf-8")
        assert SECRET not in text
        assert TOKEN not in text
        assert "hunter2" not in text
    listed = __import__("asyncio").run(build_server(connector()).list_tools())
    tools = {tool.name: tool for tool in listed}
    assert tools["cs_recon_notifications"].annotations.readOnlyHint is True
    assert tools["cs_recon_notifications"].annotations.openWorldHint is True
    assert len("mcp__csrecon__cs_recon_notifications") == 36
    assert len("mcp__csrecon__cs_recon_rules") == 28
    missing = connector().health(live=False)
    assert missing.detail in {"not configured", "offline ok"}


def test_snapshot_and_stale_results_carry_a_warning(tmp_path, monkeypatch):
    _keys(monkeypatch)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    _operator_snapshots(monkeypatch)
    snap = cs_recon_notifications(since="2026-06-01")
    assert snap["cache"] == "snapshot"
    assert snap["data"]
    assert any("operator-supplied snapshot" in warning for warning in snap["warnings"])
    rules = cs_recon_rules()
    assert rules["cache"] == "snapshot"
    assert any("CYBERAU_CSRECON_RULES_SNAPSHOT" in warning for warning in rules["warnings"])
    monkeypatch.delenv("CYBERAU_CSRECON_SNAPSHOT")
    monkeypatch.delenv("CYBERAU_CSRECON_RULES_SNAPSHOT")
    monkeypatch.delenv("CYBERAU_OFFLINE")
    _transport(_ok_handler([]))
    assert cs_recon_notifications(limit=10)["warnings"] == []
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    stale = cs_recon_notifications(limit=10)
    assert stale["cache"] == "stale"
    assert any("Cached copy" in warning for warning in stale["warnings"])


def test_snapshot_never_becomes_a_stored_finding(tmp_path, monkeypatch):
    _keys(monkeypatch)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    _operator_snapshots(monkeypatch)
    watch = Watchlist(domains=["example.com.au"])
    assert connector().exposure_for(watch, date(2026, 6, 1)) == []
    path = tmp_path / "watchlists"
    path.mkdir()
    (path / "org-exposure.yaml").write_text("domains: [example.com.au]\n", encoding="utf-8")
    assert cs_recon_notifications(since="2026-06-01")["cache"] == "snapshot"
    intel = tmp_path / "intel.sqlite"
    if intel.exists():
        rows = sqlite3.connect(intel).execute("select count(*) from exposures").fetchone()
        assert rows[0] == 0


def test_live_health_is_not_ok_without_a_credential_or_on_timeout(tmp_path, monkeypatch):
    _keys(monkeypatch)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("FALCON_CLIENT_SECRET")
    live = connector().health(live=True)
    assert live.ok is False
    assert "FALCON_CLIENT_SECRET" in live.detail
    assert connector().health(live=False).ok is True
    _keys(monkeypatch)

    def time_out(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    _transport(time_out)
    timed = connector().health(live=True)
    assert timed.ok is False
    assert "timed out" in timed.detail
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    _transport(_ok_handler([]))
    offline = connector().health(live=True)
    assert offline.ok is False


def test_since_must_be_a_real_date(tmp_path, monkeypatch):
    _keys(monkeypatch)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    for bad in ("2026-13-45", "0001-01-01", "２０２６-06-01"):
        found = cs_recon_notifications(since=bad)
        assert found["data"] == []
        assert "YYYY-MM-DD" in found["warnings"][0]


def _fixture_values() -> list[str]:
    values = [item["id"] for item in NOTIFICATIONS["resources"]]
    values += [item["id"] for item in RULES["resources"]]
    values += [item["rule_name"] for item in NOTIFICATIONS["resources"] if item.get("rule_name")]
    values += [item["name"] for item in RULES["resources"] if item.get("name")]
    return values


def _assert_unavailable(found: dict) -> None:
    assert found["data"] == []
    assert any("is unavailable" in warning for warning in found["warnings"])
    text = json.dumps(found)
    for value in _fixture_values():
        assert value not in text, value


def test_offline_without_snapshot_is_unavailable_not_synthetic(tmp_path, monkeypatch):
    _keys(monkeypatch)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    _assert_unavailable(cs_recon_notifications(since="2026-06-01"))
    _assert_unavailable(cs_recon_rules())
    watch = Watchlist(domains=["example.com.au"])
    assert connector().exposure_for(watch, date(2026, 6, 1)) == []


def test_failed_live_fetch_without_snapshot_is_unavailable(tmp_path, monkeypatch):
    _keys(monkeypatch)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))

    def time_out(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    _transport(time_out)
    _assert_unavailable(cs_recon_notifications(limit=10))
    _assert_unavailable(cs_recon_rules())

    def server_error(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/oauth2/token"):
            return httpx.Response(201, json={"access_token": TOKEN, "expires_in": 1799})
        return httpx.Response(500, json={"errors": [{"code": 500, "message": "down"}]})

    source._CACHE = None
    clear_session_caches()
    _transport(server_error)
    _assert_unavailable(cs_recon_notifications(limit=10))
    _assert_unavailable(cs_recon_rules())
