import json
import time
from pathlib import Path

import cyberau_asd_essentials.source as source
import httpx
import pytest
from cyberau_asd_essentials.source import (
    chapter_problem,
    connector,
    e8_requirements,
    essentials_chapter,
    essentials_transition,
    parse_catalog,
    parse_chapter,
    parse_transition,
    schema_drift,
    strategies_for,
)
from cyberau_common.server import build_server

FIXTURES = Path(__file__).resolve().parent / "fixtures"
DATA = Path(__file__).resolve().parents[1] / "data"
ENTERPRISE = "https://www.cyber.gov.au/publication/essentials-for-enterprise-it"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    _write_fixture_snapshot(snapshot)
    monkeypatch.setenv("CYBERAU_E8_SNAPSHOT", str(snapshot))
    source._SLEEP = lambda _seconds: None
    yield
    source._TRANSPORT = None
    source._SLEEP = time.sleep


def test_strategy_assignment_follows_section_and_statement():
    document = json.loads((FIXTURES / "E8_ML2_resolved.json").read_text(encoding="utf-8"))
    rows = parse_catalog(document)
    by_id = {}
    for row in rows:
        by_id.setdefault(row["control_id"], set()).add(row["strategy"])
    assert by_id["ism-0843"] == {"application_control"}
    assert by_id["ism-1671"] == {"restrict_office_macros"}
    assert by_id["ism-1859"] == {"user_application_hardening"}
    assert by_id["ism-1876"] == {"patch_applications"}
    assert by_id["ism-1877"] == {"patch_operating_systems"}
    assert by_id["ism-0123"] == {""}
    assert strategies_for(
        "Vulnerability scanning",
        "An automated method of asset discovery is used at least fortnightly.",
    ) == ["patch_applications", "patch_operating_systems"]
    publishers = "Microsoft Office's list of trusted publishers is validated at least annually."
    assert strategies_for("Office productivity suites", publishers) == ["restrict_office_macros"]
    assert strategies_for(
        "Hardening operating system configurations",
        "Memory integrity functionality is enabled.",
    ) == ["restrict_admin_privileges"]
    assert strategies_for(
        "Hardening operating system configurations",
        "Internet Explorer 11 is disabled or removed.",
    ) == ["user_application_hardening"]


def test_chapter_parser_keeps_phases_out_of_maturity():
    page = parse_chapter(
        (FIXTURES / "essentials_enterprise_it.html").read_text(encoding="utf-8"),
        "enterprise-it",
        ENTERPRISE,
    )
    assert chapter_problem(page) is None
    assert page["published"] == "15 Oct 2026"
    assert page["priority_phases"][0]["phase"] == 1
    assert page["priority_phases"][0]["domains"] == ["Boundary services", "Identity services"]
    assert page["priority_phases"][0]["not_a_maturity_level"] is True
    assert "maturity_level" not in page["priority_phases"][0]
    assert page["principles"][0]["id"] == "GOV-01"
    follow_up = page["actions"][1]
    assert follow_up["principle_id"] == "GOV-01"
    assert follow_up["action"] == "Review the accountabilities."
    mfa = next(row for row in page["actions"] if "MFA" in row["action"])
    assert mfa["domains"] == ["Boundary services"]
    assert mfa["attack"] == "Valid Accounts"
    changed = parse_chapter(
        (FIXTURES / "page_layout_changed.html").read_text(encoding="utf-8"),
        "enterprise-it",
        ENTERPRISE,
    )
    assert chapter_problem(changed)


def test_rowspan_keeps_the_principle_on_the_following_action():
    page = parse_chapter(
        """
        <html><body><div class="layout-content-sidebar__main">
        <table>
        <tr><th>Domain</th><th>Description</th><th>Risk Context</th></tr>
        <tr><td>Boundary services</td><td>Edge.</td><td>Exposed.</td></tr>
        </table>
        <table>
        <tr><th>Principle</th><th>Action</th><th>MITRE ATT&CK</th><th>Boundary services</th></tr>
        <tr><td rowspan="2">PRO-13 - Identity management</td><td>First action.</td>
        <td>Valid Accounts</td><td>✔</td></tr>
        <tr><td>Use phishing-resistant MFA.</td><td>Brute Force</td><td>✔</td></tr>
        </table>
        </div></body></html>
        """,
        "enterprise-it",
        ENTERPRISE,
    )
    follow = page["actions"][1]
    assert follow["principle_id"] == "PRO-13"
    assert follow["action"] == "Use phishing-resistant MFA."
    assert follow["attack"] == "Brute Force"
    assert follow["domains"] == ["Boundary services"]


def test_cloud_phase_figure_is_not_invented_and_privileged_column_matches():
    page = parse_chapter(
        (FIXTURES / "essentials_cloud.html").read_text(encoding="utf-8"),
        "cloud",
        source.CHAPTERS["cloud"],
    )
    assert page["priority_phases"] == []
    assert "No phase order" in page["priority_phases_note"]
    action = page["actions"][0]
    assert action["domains"] == ["Privileged systems"]
    assert action["shared_responsibility"]["PaaS shared responsibility"] == "C"
    ids = [item["id"] for item in page["principles"]]
    assert "PRO-04" in ids
    assert "GOV-09" in ids


def test_requirements_are_maturity_levels_and_text_is_untrusted():
    record = e8_requirements("application_control", 1)
    assert record["data"]["scale"] == "essential_eight_maturity_level"
    assert record["data"]["not_an_essentials_priority_phase"] is True
    assert record["data"]["controls"][0]["control_id"] == "ism-0843"
    assert "<<untrusted source=e8>>" in record["data"]["controls"][0]["statement"]
    assert record["attribution"].startswith("Essential Eight")
    assert e8_requirements("application_control", 3)["warnings"]
    assert e8_requirements("application_control", True)["warnings"]
    missing = e8_requirements("patch_applications", 1)
    assert [row["control_id"] for row in missing["data"]["controls"]] == ["ism-1876"]


def test_chapter_domain_filter_and_transition_quote():
    chapter = essentials_chapter("enterprise-it")
    assert chapter["data"]["priority_phases"][0]["not_a_maturity_level"] is True
    assert "maturity_level" not in chapter["data"]["priority_phases"][0]
    filtered = essentials_chapter("enterprise-it", domain="Boundary services")
    assert filtered["data"]["actions"]
    assert all("Boundary services" in row["domains"] for row in filtered["data"]["actions"])
    empty = essentials_chapter("enterprise-it", domain="Not a domain")
    assert empty["warnings"]
    assert empty["data"]["actions"] == []
    transition = essentials_transition("application control")
    assert "Trustworthy software" in transition["data"]["principles"][0]
    assert "<<untrusted source=e8>>" in transition["data"]["principles"][0]
    assert "<<untrusted source=e8>>" in transition["data"]["mappings"][0]["action"]
    assert "<<untrusted source=e8>>" in transition["data"]["mappings"][0]["domain_coverage"]
    mature = e8_requirements("application_control", 2)
    assert mature["data"]["cross_cutting"][0]["control_id"] == "ism-0123"
    assert any("cross_cutting" in item for item in mature["warnings"])
    assert essentials_transition("example")["warnings"]
    assert essentials_transition("example")["data"] is None


def test_schema_drift_and_malformed_catalog():
    assert schema_drift({"controls": []}, {"chapters": {}})
    healthy_maturity, healthy_essentials, problem = source._snapshot_pair()
    assert problem == ""
    assert schema_drift(healthy_maturity, healthy_essentials) is None
    drifted = json.loads(json.dumps(healthy_maturity))
    drifted.pop("controls")
    drifted["items"] = []
    assert schema_drift(drifted, healthy_essentials)
    probe = connector().health(live=False, check_schema=True)
    assert probe.ok is True
    assert parse_catalog({"not": "a catalog"}) == []
    assert parse_catalog({"catalog": {"groups": [{"controls": [{"id": "ism-1"}]}]}})


def test_live_health_does_not_treat_failure_as_ok(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")

    def denied(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, content=b"no")

    source._TRANSPORT = httpx.MockTransport(denied)
    probe = connector().health(live=True)
    assert probe.ok is False
    assert "403" in probe.detail
    assert "no API key" in probe.detail
    assert "live ok" not in probe.detail


def test_redirect_is_refused(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")

    def redirect(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/stolen"})

    source._TRANSPORT = httpx.MockTransport(redirect)
    text, _cache, warning = source._http(ENTERPRISE, ttl=60, skip_cache=True)
    assert text is None
    assert "evil.example" in warning or "allow" in warning.lower()


def test_timeout_falls_back_and_retry_after_is_honoured(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    waits = []
    source._SLEEP = waits.append

    def timeout(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    source._TRANSPORT = httpx.MockTransport(timeout)
    text, cache, warning = source._http(ENTERPRISE, ttl=60, skip_cache=True)
    assert text is None
    assert cache == "snapshot"
    assert warning

    calls = {"count": 0}

    def limited(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        if calls["count"] == 1:
            return httpx.Response(429, headers={"retry-after": "7"}, content=b"slow")
        return httpx.Response(200, content=b"<html>essentials priority phase</html>")

    source._TRANSPORT = httpx.MockTransport(limited)
    text, _cache, warning = source._http(ENTERPRISE, ttl=60, skip_cache=True)
    assert text
    assert warning == ""
    assert 7 in waits


def test_tool_schemas_match_the_ticket():
    import asyncio

    tools = {tool.name: tool for tool in asyncio.run(build_server(connector()).list_tools())}
    assert tools["e8_requirements"].inputSchema["required"] == ["strategy", "maturity_level"]
    assert "patch_applications" in json.dumps(tools["e8_requirements"].inputSchema)
    assert tools["essentials_chapter"].annotations.readOnlyHint is True
    assert len("mcp__e8__essentials_transition") == 30


def test_shipped_snapshot_when_present():
    maturity = DATA / "e8-maturity-v2026.09.4.json"
    essentials = DATA / "essentials-2026-10-17.json"
    if not maturity.is_file() or not essentials.is_file():
        pytest.skip("shipped snapshot is built by rebuild_shipped_snapshot")
    document = json.loads(maturity.read_text(encoding="utf-8"))
    assigned = {(row["control_id"], row["strategy"]) for row in document["controls"]}
    assert ("ism-0843", "application_control") in assigned
    assert ("ism-1173", "multi_factor_authentication") in assigned
    assert ("ism-1511", "regular_backups") in assigned
    assert "ism-0123" in document["unassigned_control_ids"]
    document_root = json.loads(essentials.read_text(encoding="utf-8"))
    chapters = document_root["chapters"]
    hardening = document_root["transition"]["strategies"]["user_application_hardening"]
    assert "Content filtering" in hardening["principles"]
    assert "." not in hardening["principles"]
    assert document_root["transition"]["strategies"]["application_control"]["mappings"]
    assert chapters["enterprise-it"]["priority_phases"]
    assert chapters["ot"]["priority_phases"]
    assert chapters["cloud"]["priority_phases"] == []
    assert chapters["enterprise-it"]["priority_phases_are_not_maturity_levels"] is True


def _write_fixture_snapshot(snapshot: Path) -> None:
    enterprise = parse_chapter(
        (FIXTURES / "essentials_enterprise_it.html").read_text(encoding="utf-8"),
        "enterprise-it",
        ENTERPRISE,
    )
    catalog = json.loads((FIXTURES / "E8_ML2_resolved.json").read_text(encoding="utf-8"))
    parsed = parse_catalog(catalog)
    rows = [row for row in parsed if row["strategy"]]
    unassigned = [row for row in parsed if not row["strategy"]]
    transition = parse_transition(
        """
        <html><body><div class="layout-content-sidebar__main">
        <h2>Strategy-by-strategy transition mapping</h2>
        <table>
        <tr><th>Essential Eight mitigation strategy</th><th>Mapped principles</th></tr>
        <tr><td>Application control</td><td>Trustworthy software</td></tr>
        </table>
        <h3>Application control</h3>
        <table>
        <tr><th>Principle</th><th>Action</th>
        <th>Domain coverage</th><th>Existing E8 contribution</th></tr>
        <tr>
          <td>Trustworthy software</td><td>Permit only approved software.</td>
          <td>User devices (ML1)</td><td>Existing rulesets.</td>
        </tr>
        </table>
        </div></body></html>
        """
    )
    (snapshot / "e8-maturity-v2026.09.4.json").write_text(
        json.dumps(
            {
                "ism_release": "v2026.09.4",
                "retrieved_on": "2026-10-17",
                "source_urls": ["https://raw.githubusercontent.com/example"],
                "controls": rows,
                "unassigned_controls": unassigned,
                "unassigned_control_ids": [row["control_id"] for row in unassigned],
            }
        ),
        encoding="utf-8",
    )
    (snapshot / "essentials-2026-10-17.json").write_text(
        json.dumps(
            {
                "retrieved_on": "2026-10-17",
                "chapters": {"enterprise-it": enterprise, "cloud": enterprise, "ot": enterprise},
                "transition": transition,
            }
        ),
        encoding="utf-8",
    )
