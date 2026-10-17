"""Contract suite every premium connector must pass."""

from __future__ import annotations

import json
import logging
from datetime import date

import pytest
from cyberau_premium.base import Watchlist
from cyberau_premium.budget import BudgetLedger
from cyberau_premium.caching import cache_for_terms
from cyberau_premium.catalog import load_vendors
from cyberau_premium.guard import pre_tool_call
from cyberau_premium.redact import redact_text
from cyberau_premium.samples import SCHEMA, sample_finding
from cyberau_premium.status import load_servers, render_premium_servers
from cyberau_premium.stix import export_stix
from cyberau_premium.store import ExposureStore
from jsonschema import Draft202012Validator

VALIDATOR = Draft202012Validator(SCHEMA, format_checker=Draft202012Validator.FORMAT_CHECKER)
SECRET = "hunter2-secret"


def test_v02_vendor_is_covered():
    covered = {spec.server for spec in load_vendors() if spec.milestone == "v0.2"}
    assert {"upguard", "recordedfuture", "flare", "ransomlive"} <= covered


def test_off_by_default(connector, vendor):
    entry = load_servers()[vendor.server]
    assert entry["default_enabled"] is False
    assert entry["enabled_by_default"] is False
    assert entry["connector"] == vendor.package
    env = {name: "present" for name in [*vendor.licence_env, *vendor.optional_env]}
    rendered = render_premium_servers(load_servers(), env=env)
    assert rendered[vendor.server]["enabled"] is False
    assert "present" not in json.dumps(rendered[vendor.server])
    assert connector.terms is not None


def test_no_key_reports_not_configured(connector, vendor, monkeypatch):
    for name in [*vendor.licence_env, *vendor.optional_env]:
        monkeypatch.delenv(name, raising=False)
    detail = connector.health_result().detail
    if vendor.licence_env:
        assert detail == "not configured"
    else:
        assert detail == "offline ok"
    with pytest.raises(NotImplementedError):
        connector.exposure_for(Watchlist(domains=["example.com.au"]), date(2026, 6, 1))


def test_terms_cache_none_never_hits_disk(connector, tmp_path):
    terms = connector.terms.model_copy(update={"cache": "none", "cache_ttl_max_s": 0})
    path = tmp_path / "http_cache.sqlite"
    cache = cache_for_terms(path, terms)
    key = cache.key("GET", "https://example.com/a", None, b"body", "scope")
    cache.put(
        key,
        status=200,
        headers={"content-type": "application/json"},
        body=b"secret-body",
        ttl=60,
    )
    assert cache.get(key) is None
    assert not path.exists()
    assert not list(tmp_path.glob("*.sqlite*"))

    own = tmp_path / "own.sqlite"
    real = cache_for_terms(own, connector.terms)
    real.put(key, status=200, headers={}, body=b"cached-body", ttl=60)
    if connector.terms.cache in {"none", "session"}:
        assert not own.exists()
    if connector.terms.cache == "session":
        assert real.get(key) is not None
        real.clear_session()
        assert real.get(key) is None


def test_store_metadata_drops_values(connector, tmp_path):
    terms = connector.terms.model_copy(update={"store": "metadata"})
    finding = sample_finding(connector.vendor, terms)
    store = ExposureStore(tmp_path / "intel.sqlite")
    status = store.write(
        finding,
        terms=terms,
        watchlist=Watchlist(domains=["example.com.au"]),
        values={"password": SECRET, "cookie": "sess-abc"},
    )
    assert status == "stored"
    blob = (tmp_path / "intel.sqlite").read_bytes()
    assert SECRET.encode() not in blob
    assert b"sess-abc" not in blob
    row = store.get(finding.finding_id)
    assert row["licence_scope"] == "store_metadata"
    assert "employees" in row["counts_json"]
    assert row["subject_value"] == "example.com.au"


def test_stix_skips_non_exportable(connector, tmp_path):
    finding = sample_finding(connector.vendor, connector.terms, stix_exportable=True)
    store = ExposureStore(tmp_path / "intel.sqlite")
    store.write(
        finding,
        terms=connector.terms,
        watchlist=Watchlist(domains=["example.com.au"]),
    )
    report = export_stix(store)
    assert report["exported"] == 0
    assert report["skipped"] == 1
    assert report["objects"] == []
    assert finding.finding_id not in json.dumps(report)


def test_budget_blocks_over_limit(connector, vendor, tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    for name in vendor.licence_env:
        monkeypatch.setenv(name, "present")
    ledger = BudgetLedger(tmp_path / "premium-ledger.sqlite")
    config = {
        "mcp_servers": {vendor.server: {"enabled": True}},
        "cyber_au": {"premium": {vendor.server: {"quota": {"calls_per_day": 1}}}},
    }
    tool = vendor.tool_prefixes[0] + "probe"
    with caplog.at_level(logging.WARNING, logger="cyberau.premium"):
        first = pre_tool_call(tool_name=tool, config=config, ledger=ledger)
        second = pre_tool_call(tool_name=tool, config=config, ledger=ledger)
    assert first["decision"] == "allow"
    assert second["block"] is True
    assert "calls_per_day" in second["message"]
    assert vendor.server in second["message"]
    assert any("calls_per_day" in record.message for record in caplog.records)
    assert ledger.usage(vendor.server).calls_today == 1
    assert "present" not in second["message"]


def test_redaction(connector):
    text = (
        "password=hunter2 cookie=sess-abc token=tok-xyz "
        "Bearer eyJhbGciOi.payload.sig ada@example.com.au"
    )
    cleaned = redact_text(text)
    secrets = (
        "hunter2",
        "sess-abc",
        "tok-xyz",
        "eyJhbGciOi.payload.sig",
        "ada@example.com.au",
    )
    for secret in secrets:
        assert secret not in cleaned
    assert "password:" in cleaned
    assert "cookie:" in cleaned
    assert "token:" in cleaned
    assert "email:" in cleaned
    assert connector.vendor


def test_findings_match_schema(connector):
    finding = sample_finding(connector.vendor, connector.terms)
    payload = finding.model_dump(mode="json", exclude_none=True)
    VALIDATOR.validate(payload)
