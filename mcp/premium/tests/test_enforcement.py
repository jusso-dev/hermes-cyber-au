"""Budgets, terms, store retention and doctor behaviour."""

from __future__ import annotations

import importlib.util
import json
import logging
import re
from datetime import UTC, datetime, timedelta

from cyberau_premium.base import TermsProfile, Watchlist
from cyberau_premium.briefing import filter_for_delivery
from cyberau_premium.budget import BudgetLedger
from cyberau_premium.caching import cache_for_terms
from cyberau_premium.catalog import TermsRejected, apply_terms, get_vendor, load_vendors
from cyberau_premium.docs import render_vendor_terms, terms_dir
from cyberau_premium.guard import on_session_end, pre_tool_call
from cyberau_premium.paths import repo_root
from cyberau_premium.samples import OBSERVED, sample_finding
from cyberau_premium.status import format_premium_doctor, load_servers, render_premium_servers
from cyberau_premium.stix import export_stix
from cyberau_premium.store import ExposureStore

_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b")
_HOST = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+(?:[a-z]{2,})\b")
_ALLOWED = ("example.com", "example.com.au", "example.au")


def _enabled(server: str, quota: dict | None = None) -> dict:
    premium: dict = {}
    if quota:
        premium[server] = {"quota": quota}
    return {
        "mcp_servers": {server: {"enabled": True}},
        "cyber_au": {"premium": premium},
    }


def test_fresh_install_stays_off_when_every_key_is_set():
    env = {}
    for spec in load_vendors():
        for name in [*spec.licence_env, *spec.optional_env]:
            env[name] = "sentinel-value"
    rendered = render_premium_servers(load_servers(), env=env)
    assert set(rendered) == {spec.server for spec in load_vendors()}
    blob = json.dumps(rendered)
    assert "sentinel-value" not in blob
    assert all(entry["enabled"] is False for entry in rendered.values())
    kept = render_premium_servers(load_servers(), env=env, user_enabled={"upguard": True})
    assert kept["upguard"]["enabled"] is True
    assert kept["flare"]["enabled"] is False


def test_doctor_states_and_usage(tmp_path):
    ledger = BudgetLedger(tmp_path / "premium-ledger.sqlite")
    now = datetime(2026, 6, 15, 1, 0, tzinfo=UTC)
    env = {"UPGUARD_API_KEY": "present", "FLARE_API_KEY": ""}
    enabled = {"recordedfuture": True, "flare": True}
    report = format_premium_doctor(env, enabled, ledger, now=now)
    assert "upguard: off (paid, bring your own licence)" in report
    assert "recordedfuture: on, key missing" in report
    assert "flare: on, key missing" in report
    assert "ransomlive: off (free feed, disabled until you enable it)" in report
    assert "Australia/Sydney" in report
    assert "day 0/24" in report
    assert "month 0/500000" in report
    on = format_premium_doctor({"UPGUARD_API_KEY": "present"}, {"upguard": True}, ledger, now=now)
    assert "upguard: on\n" in on
    assert "upguard: on, key missing" not in on


def test_routine_share_and_approval_and_pages(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("UPGUARD_API_KEY", "present")
    ledger = BudgetLedger(tmp_path / "ledger.sqlite")
    config = _enabled("upguard", {"calls_per_day": 4, "routine_share": 0.5})
    with caplog.at_level(logging.WARNING, logger="cyberau.premium"):
        assert (
            pre_tool_call(tool_name="upguard_probe", config=config, ledger=ledger, routine=True)[
                "decision"
            ]
            == "allow"
        )
        assert (
            pre_tool_call(tool_name="upguard_probe", config=config, ledger=ledger, routine=True)[
                "decision"
            ]
            == "allow"
        )
        blocked = pre_tool_call(
            tool_name="upguard_probe", config=config, ledger=ledger, routine=True
        )
    assert blocked["decision"] == "block"
    assert "calls_per_day" in blocked["message"]
    assert "routine share" in blocked["message"]
    assert ledger.usage("upguard").calls_today == 2

    ask_ledger = BudgetLedger(tmp_path / "ask.sqlite")
    ask_config = _enabled("upguard", {"approval_above_units": 1, "cost_units_per_call": 2})
    asked = pre_tool_call(tool_name="upguard_probe", config=ask_config, ledger=ask_ledger)
    assert asked["needs_approval"] is True
    assert "approval_above_units" in asked["message"]
    assert ask_ledger.usage("upguard").calls_today == 0
    allowed = pre_tool_call(
        tool_name="upguard_probe",
        config=ask_config,
        ledger=ask_ledger,
        approved=True,
    )
    assert allowed["decision"] == "allow"
    assert ask_ledger.usage("upguard").calls_today == 1

    page_ledger = BudgetLedger(tmp_path / "pages.sqlite")
    paged = pre_tool_call(
        tool_name="upguard_probe",
        args={"pages": 6},
        config=_enabled("upguard"),
        ledger=page_ledger,
    )
    assert paged["decision"] == "block"
    assert "max_pages" in paged["message"]
    assert page_ledger.usage("upguard").calls_today == 0
    assert any("max_pages" in record.message for record in caplog.records)


def test_terms_relax_needs_contract_ref(tmp_path):
    spec = get_vendor("upguard")
    config = {"cyber_au": {"premium": {"upguard": {"terms": {"stix_export": True}}}}}
    try:
        apply_terms(spec, config)
        raised = False
    except TermsRejected:
        raised = True
    assert raised
    audit = tmp_path / "audit.jsonl"
    applied = apply_terms(
        spec,
        {
            "cyber_au": {
                "premium": {"upguard": {"terms": {"stix_export": True, "contract_ref": "CN-100"}}}
            }
        },
        audit_path=audit,
    )
    assert applied.stix_export is True
    record = json.loads(audit.read_text(encoding="utf-8").strip())
    assert record["contract_ref"] == "CN-100"
    assert "stix_export" in record["relaxed"]
    tightened = apply_terms(
        spec,
        {"cyber_au": {"premium": {"upguard": {"terms": {"cache": "none"}}}}},
    )
    assert tightened.cache == "none"


def test_store_dedupe_retention_and_third_parties(tmp_path):
    spec = get_vendor("flare")
    store = ExposureStore(tmp_path / "intel.sqlite")
    watch = Watchlist(domains=["example.com.au"], exclude=["other.example.com.au"])
    first = sample_finding("flare", spec.terms, counts={"employees": 1})
    later = sample_finding(
        "flare",
        spec.terms,
        counts={"employees": 4},
        observed_at=OBSERVED + timedelta(days=3),
    )
    moment = datetime(2026, 6, 2, tzinfo=UTC)
    assert store.write(first, terms=spec.terms, watchlist=watch, now=moment) == "stored"
    assert store.write(later, terms=spec.terms, watchlist=watch, now=moment) == "updated"
    row = store.get(first.finding_id)
    assert row["observed_at"].startswith("2026-06-04")
    assert json.loads(row["counts_json"])["employees"] == 4
    assert row["first_seen"].startswith("2026-06-01")
    expected_expiry = (moment + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert row["expires_at"] == expected_expiry

    outsider = sample_finding(
        "flare",
        spec.terms,
        subject_value="other.example.com.au",
        source_ref="ext",
    )
    assert store.write(outsider, terms=spec.terms, watchlist=watch) == "dropped_third_party"
    assert store.get(outsider.finding_id) is None

    claim = sample_finding(
        "flare",
        spec.terms,
        kind="leak_site_claim",
        confidence="vendor_reported",
        source_ref="claim-1",
    )
    assert store.write(claim, terms=spec.terms, watchlist=watch) == "stored"
    assert store.get(claim.finding_id)["confidence"] == "unverified_claim"

    old = ExposureStore(tmp_path / "old.sqlite")
    aged = sample_finding("flare", spec.terms, source_ref="old")
    old.write(aged, terms=spec.terms, watchlist=watch, now=datetime(2020, 1, 1, tzinfo=UTC))
    assert old.delete_expired(datetime(2026, 1, 1, tzinfo=UTC)) == 1
    assert old.get(aged.finding_id) is None


def test_stix_exports_only_allowed_findings(tmp_path):
    terms = TermsProfile(
        cache="none",
        store="metadata",
        stix_export=True,
        attribution="Test profile for export.",
    )
    store = ExposureStore(tmp_path / "intel.sqlite")
    watch = Watchlist(domains=["example.com.au"])
    hidden = sample_finding("upguard", terms, source_ref="hidden", stix_exportable=False)
    shown = sample_finding("upguard", terms, source_ref="shown", stix_exportable=True)
    store.write(hidden, terms=terms, watchlist=watch)
    store.write(shown, terms=terms, watchlist=watch)
    report = export_stix(store)
    assert report["exported"] == 1
    assert report["skipped"] == 1
    dumped = json.dumps(report)
    assert shown.finding_id in dumped
    assert hidden.finding_id not in dumped


def test_briefing_drops_unshared_findings():
    spec = get_vendor("recordedfuture")
    finding = sample_finding("recordedfuture", spec.terms)
    kept = filter_for_delivery(
        [finding],
        {"recordedfuture": spec.terms},
        target="owner",
        owner="owner",
    )
    assert kept == [finding]
    dropped = filter_for_delivery(
        [finding],
        {"recordedfuture": spec.terms},
        target="team-channel",
        owner="owner",
    )
    assert dropped == []


def test_session_cache_clears_and_ttl_is_capped(tmp_path):
    session_terms = TermsProfile(cache="session", store="metadata", attribution="Session only.")
    path = tmp_path / "session.sqlite"
    cache = cache_for_terms(path, session_terms)
    key = cache.key("GET", "https://example.com/a", None, b"", "scope")
    cache.put(key, status=200, headers={}, body=b"memo", ttl=30)
    assert cache.get(key) is not None
    on_session_end()
    assert cache.get(key) is None
    assert not path.exists()

    ttl_terms = TermsProfile(
        cache="ttl",
        cache_ttl_max_s=10,
        store="metadata",
        attribution="Short ttl.",
    )
    disk = cache_for_terms(tmp_path / "ttl.sqlite", ttl_terms)
    disk.put(key, status=200, headers={}, body=b"memo", ttl=500)
    assert disk.get(key).ttl == 10


def test_terms_docs_and_readme():
    for spec in load_vendors():
        path = terms_dir() / f"{spec.server}.md"
        assert path.read_text(encoding="utf-8") == render_vendor_terms(spec)
    readme = (repo_root() / "docs" / "premium" / "README.md").read_text(encoding="utf-8")
    for phrase in (
        "bring your own licence",
        "cache",
        "store",
        "stix_export",
        "share_outside_profile",
        "redistribution",
        "monthly_budget_units",
        "Australia/Sydney",
        "Australian Privacy Principles",
        "APP 8",
        "not legal advice",
        "unverified_claim",
    ):
        assert phrase in readme
    for spec in load_vendors():
        assert f"terms/{spec.server}.md" in readme
    assert "\u2014" not in readme
    assert "\u2013" not in readme


def test_hook_reexports_guard():
    path = repo_root() / "plugins" / "cyber-au" / "hooks" / "premium_guard.py"
    spec = importlib.util.spec_from_file_location("premium_guard_hook", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    assert module.pre_tool_call is pre_tool_call
    assert module.on_session_end is on_session_end


def test_fixtures_are_synthetic():
    fixtures = repo_root() / "mcp" / "premium" / "tests" / "fixtures"
    for path in fixtures.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for match in _EMAIL.finditer(text):
            assert match.group(1).lower() in _ALLOWED
        for host in _HOST.findall(text):
            assert _allowed_host(host.lower()), host


def _allowed_host(host: str) -> bool:
    if host in _ALLOWED:
        return True
    return (
        host.endswith(".example.com")
        or host.endswith(".example.com.au")
        or host.endswith(".example.au")
    )


def test_guard_blocks_when_the_server_is_off(tmp_path):
    ledger = BudgetLedger(tmp_path / "ledger.sqlite")
    blocked = pre_tool_call(tool_name="flare_tenant_exposure", ledger=ledger)
    assert blocked["decision"] == "block"
    assert "off (paid, bring your own licence)" in blocked["message"]
    assert ledger.usage("flare").calls_today == 0
    ignored = pre_tool_call(tool_name="kev_lookup", ledger=ledger)
    assert ignored["decision"] == "allow"
