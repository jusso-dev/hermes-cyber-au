"""Exposure findings for the briefing, triage, NDB and executive page. Synthetic data only."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest
from cyberau_org_exposure.briefing import brief_payload, finding_payload, premium_state, trend
from cyberau_org_exposure.cli import main
from cyberau_org_exposure.findings import store_findings
from cyberau_premium.base import TermsProfile, Watchlist
from cyberau_premium.stix import export_stix
from cyberau_premium.store import ExposureStore

NOW = datetime(2026, 10, 20, 7, 30, tzinfo=ZoneInfo("Australia/Sydney"))
DOMAIN = "example.com.au"


def _finding(vendor, kind, ref, observed, **extra):
    return {
        "finding_id": f"{vendor}-{kind}-{ref}",
        "vendor": vendor,
        "kind": kind,
        "subject": {"type": "domain", "value": DOMAIN, "watchlist_entry": "wl-1"},
        "observed_at": observed,
        "first_seen": extra.pop("first_seen", observed),
        "licence_scope": "store_metadata",
        "confidence": extra.pop("confidence", "vendor_reported"),
        "counts": extra.pop("counts", {"employees": 2}),
        "data_classes": extra.pop("data_classes", ["email address", "password"]),
        "stix_exportable": extra.pop("stix_exportable", False),
        "contains_personal_information": extra.pop("contains_personal_information", True),
        **extra,
    }


@pytest.fixture
def data(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("HERMES_HOME", raising=False)
    return tmp_path


def _enabled(*servers):
    return {"mcp_servers": {name: {"enabled": True} for name in servers}}


def test_no_store_and_no_premium_vendor_gives_an_empty_section_input(data):
    payload = brief_payload(now=NOW, config={})
    assert payload["untrusted"] is True
    assert payload["data"]["premium_enabled"] == []
    assert payload["data"]["findings"] == []


def test_premium_state_reads_enabled_paid_vendors_and_share_terms():
    enabled, share = premium_state(_enabled("hudsonrock", "ransomlive"))
    # ransomlive is the free tracker, not a premium vendor.
    assert enabled == ["hudsonrock"]
    assert share["hudsonrock"] is False
    relaxed = {
        "cyber_au": {
            "premium": {
                "upguard": {"terms": {"share_outside_profile": True, "contract_ref": "CN-1"}}
            }
        }
    }
    _enabled_list, share = premium_state(relaxed)
    assert share["upguard"] is True


def test_new_findings_since_the_last_briefing_and_recording(data):
    store_findings(
        [
            _finding("hudsonrock", "infostealer_credential", "a", "2026-10-19T12:00:00Z"),
            _finding("ransomlive", "leak_site_claim", "b", "2026-10-19T10:00:00Z"),
            _finding("upguard", "typosquat_domain", "old", "2026-09-01T00:00:00Z"),
        ]
    )
    first = brief_payload(now=NOW, config=_enabled("hudsonrock"), record=True)
    ids = [item["finding_id"] for item in first["data"]["findings"]]
    assert ids == ["ransomlive-leak_site_claim-b", "hudsonrock-infostealer_credential-a"]
    claim = first["data"]["findings"][0]
    assert claim["confidence"] == "unverified_claim"
    assert claim["share_outside_profile"] is False
    for item in first["data"]["findings"]:
        assert "data_classes" not in item
    second = brief_payload(now=NOW, config=_enabled("hudsonrock"))
    assert second["data"]["findings"] == []


def test_both_store_files_are_read_and_deduplicated(data):
    terms = TermsProfile(cache="none", store="metadata", stix_export=True, attribution="Test.")
    store = ExposureStore(data / "intel.sqlite")
    from cyberau_premium.base import ExposureFinding, Subject, finding_id

    finding = ExposureFinding(
        finding_id=finding_id("upguard", "breach_credential", DOMAIN, "r1"),
        vendor="upguard",
        kind="breach_credential",
        subject=Subject(type="domain", value=DOMAIN),
        observed_at=datetime(2026, 10, 19, 1, tzinfo=UTC),
        licence_scope="store_metadata",
        confidence="vendor_confirmed",
        source_ref="r1",
        stix_exportable=True,
        counts={"records": 40},
    )
    store.write(finding, terms=terms, watchlist=Watchlist(domains=[DOMAIN]))
    store_findings([_finding("hudsonrock", "infostealer_credential", "a", "2026-10-19T12:00:00Z")])
    payload = brief_payload(now=NOW, config=_enabled("upguard"))
    vendors = sorted(item["vendor"] for item in payload["data"]["findings"])
    assert vendors == ["hudsonrock", "upguard"]
    # STIX export from the premium store still exports only stix_exportable rows.
    assert export_stix(store)["exported"] == 1


def test_trend_is_counts_only(data):
    rows = [
        {"kind": "infostealer_credential", "observed_at": "2026-10-19T00:00:00Z"},
        {"kind": "infostealer_credential", "observed_at": "2026-10-18T00:00:00Z"},
        {"kind": "typosquat_domain", "observed_at": "2026-10-17T00:00:00Z"},
        {"kind": "typosquat_domain", "observed_at": "2026-10-08T00:00:00Z"},
    ]
    result = trend(rows, now=NOW)
    assert result["current"] == 3
    assert result["previous"] == 1
    assert result["line"] == (
        "Exposure of our organisation: 3 new findings in the last 7 days, up from 1 in the "
        "7 days before (2 infostealer_credential, 1 typosquat_domain). Counts only."
    )
    assert DOMAIN not in json.dumps(result)


def test_finding_payload_prefills_ndb_fields(data, capsys):
    store_findings(
        [
            _finding(
                "hudsonrock",
                "infostealer_credential",
                "a",
                "2026-10-19T12:00:00Z",
                first_seen="2026-10-12T00:00:00Z",
                counts={"employees": 3, "users": 12},
            )
        ]
    )
    result = finding_payload("hudsonrock-infostealer_credential-a", config={})
    finding = result["data"]["finding"]
    assert finding["data_classes"] == ["email address", "password"]
    assert finding["counts"] == {"employees": 3, "users": 12}
    assert finding["first_seen"] == "2026-10-12T00:00:00Z"
    assert finding["contains_personal_information"] is True
    assert main(["exposure-finding", "missing-id"]) == 1
    assert '"found": false' in capsys.readouterr().out


def test_cli_exposure_brief_prints_an_envelope(data, capsys):
    store_findings([_finding("hudsonrock", "infostealer_credential", "a", "2026-10-19T12:00:00Z")])
    assert main(["exposure-brief", "--since", "2026-10-19T00:00:00+11:00"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["source"] == "org-exposure"
    assert payload["data"]["findings"][0]["kind"] == "infostealer_credential"
    assert main(["exposure-brief", "--since", "yesterday"]) == 2
