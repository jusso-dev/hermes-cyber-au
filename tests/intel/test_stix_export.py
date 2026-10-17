"""STIX 2.1 export, import, TLP ceiling and bundle validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cyberau_common.cli import main
from store.api import (
    ensure_source,
    export_records,
    lookup,
    upsert_advisory,
    upsert_indicator,
    upsert_vulnerability,
)
from store.canonical import STIX_NAMESPACE, indicator_id
from store.db import open_store
from store.stix import (
    EXPORT_TYPES,
    SDO_NAMESPACE,
    TLP_NOT_EXPORTED,
    export_stix,
    import_stix,
    resolve_export_path,
)
from store.tools import intel_add_observation, intel_export_stix

HASH = "ab" * 32
_AMBER_REF = "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421"


def _schemas() -> None:
    import stix2validator

    vendor = Path(__file__).resolve().parent / "vendor" / "cti-stix2-json-schemas" / "schemas"
    dest_root = Path(stix2validator.__file__).resolve().parent / "schemas-2.1"
    dest = dest_root / "schemas"
    dest_root.mkdir(exist_ok=True)
    if not dest.exists():
        dest.symlink_to(vendor)


def _validate(text: str) -> None:
    _schemas()
    from stix2validator import validate_string

    result = validate_string(text)
    details = []
    fatal = getattr(result, "fatal", None)
    if fatal is not None:
        details.append(str(getattr(fatal, "error", fatal)))
    for item in getattr(result, "object_results", []) or []:
        for error in getattr(item, "errors", []) or []:
            details.append(str(error))
    assert result.is_valid, "\n".join(details) or repr(result)


def _seed(store_path) -> str:
    ipv4 = upsert_indicator(
        "ipv4",
        "203.0.113.10",
        source="feed",
        observed_at="2026-02-01T00:00:00Z",
        raw=b"v4",
        verdict="malicious",
        confidence=80,
        tlp="CLEAR",
        path=store_path,
    )
    upsert_indicator(
        "domain",
        "clear.example",
        source="feed",
        observed_at="2026-02-02T00:00:00Z",
        raw=b"dom-a",
        verdict="malicious",
        confidence=80,
        tlp="CLEAR",
        path=store_path,
    )
    upsert_indicator(
        "domain",
        "clear.example",
        source="feed",
        observed_at="2026-02-03T00:00:00Z",
        raw=b"dom-b",
        verdict="benign",
        confidence=80,
        tlp="CLEAR",
        path=store_path,
    )
    upsert_indicator(
        "url",
        "hxxps://Example[.]COM/a/../b#x",
        source="feed",
        observed_at="2026-02-04T00:00:00Z",
        raw=b"url",
        verdict="malicious",
        confidence=80,
        tlp="CLEAR",
        path=store_path,
    )
    upsert_indicator(
        "sha256",
        HASH,
        source="feed",
        observed_at="2026-02-05T00:00:00Z",
        raw=b"hash",
        verdict="malicious",
        confidence=90,
        tlp="CLEAR",
        path=store_path,
    )
    upsert_indicator(
        "email",
        "user@example.com",
        source="feed",
        observed_at="2026-02-06T00:00:00Z",
        raw=b"mail",
        verdict="suspicious",
        confidence=60,
        tlp="GREEN",
        path=store_path,
    )
    upsert_indicator(
        "ipv6",
        "2001:db8::10",
        source="feed",
        observed_at="2026-02-07T00:00:00Z",
        raw=b"v6",
        verdict="malicious",
        confidence=70,
        tlp="CLEAR",
        path=store_path,
    )
    intel_add_observation(
        "ipv4",
        "203.0.113.11",
        verdict="suspicious",
        note="checked the lab sample",
        path=store_path,
    )
    upsert_indicator(
        "domain",
        "strict.example",
        source="feed",
        observed_at="2026-02-08T00:00:00Z",
        raw=b"strict",
        verdict="malicious",
        confidence=80,
        tlp="AMBER+STRICT",
        path=store_path,
    )
    upsert_indicator(
        "domain",
        "red.example",
        source="feed",
        observed_at="2026-02-09T00:00:00Z",
        raw=b"red",
        verdict="malicious",
        confidence=80,
        tlp="RED",
        path=store_path,
    )
    upsert_indicator(
        "asn",
        "AS64500",
        source="feed",
        observed_at="2026-02-10T00:00:00Z",
        raw=b"asn",
        verdict="malicious",
        confidence=70,
        tlp="CLEAR",
        path=store_path,
    )
    upsert_indicator(
        "cidr",
        "203.0.113.0/24",
        source="feed",
        observed_at="2026-02-11T00:00:00Z",
        raw=b"cidr",
        tlp="CLEAR",
        path=store_path,
    )
    upsert_vulnerability(
        "CVE-2099-1000",
        path=store_path,
        kev_date_added="2026-01-01",
        kev_due_date="2026-01-15",
        kev_ransomware="Unknown",
        epss=0.5,
        epss_percentile=0.9,
        epss_date="2026-06-01",
        cwe="CWE-79",
        updated_at="2026-06-01T00:00:00Z",
    )
    ensure_source("public-feed", name="Public", default_tlp="CLEAR", path=store_path)
    ensure_source("amber-feed", name="Amber feed", default_tlp="AMBER", path=store_path)
    upsert_advisory(
        "public:1",
        source="public-feed",
        title="Public notice",
        url="https://example.com/public",
        published_at="2026-06-02T00:00:00Z",
        summary="reset the widget",
        content_sha256=None,
        path=store_path,
    )
    upsert_advisory(
        "amber:1",
        source="amber-feed",
        title="Restricted notice",
        url="https://example.com/amber",
        published_at="2026-06-02T00:00:00Z",
        summary="internal note",
        content_sha256=None,
        path=store_path,
    )
    store = open_store(store_path)
    conn = store.connection()
    conn.execute(
        "INSERT INTO advisory_refs (advisory_id, ref_type, ref) VALUES (?, ?, ?)",
        ("public:1", "cve", "CVE-2099-1000"),
    )
    conn.execute(
        """
        INSERT INTO relationships (src_id, rel, dst_id, source_id, first_seen)
        VALUES (?, ?, ?, ?, ?)
        """,
        (ipv4, "related-to", "CVE-2099-1000", "feed", "2026-06-01T00:00:00Z"),
    )
    return ipv4


def _indicator_keys(path) -> list[tuple]:
    rows = export_records(max_tlp="RED", path=path)
    return sorted(
        (row["type"], row["value_norm"], row["verdict"], row["confidence"], row["tlp"])
        for row in rows
        if row["kind"] == "indicator" and row["type"] in EXPORT_TYPES
    )


def test_clear_bundle_is_deterministic_and_valid(store_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_ORG_NAME", "cyber-au")
    ipv4 = _seed(store_path)
    first = export_stix(store=store_path)
    second = export_stix(store=store_path)
    assert first["text"] == second["text"]
    assert first["explicit_max_tlp"] is False
    assert first["max_tlp"] == "CLEAR"
    assert not (store_path.parent / "audit").exists()
    _validate(first["text"])
    bundle = first["bundle"]
    types = {item["type"] for item in bundle["objects"]}
    assert "identity" in types
    assert "ipv4-addr" in types
    assert "vulnerability" in types
    assert "report" in types
    assert "relationship" in types
    assert "sighting" not in types
    assert "autonomous-system" not in types
    text = first["text"]
    assert indicator_id("ipv4", "203.0.113.10") == ipv4
    assert f'"id": "{ipv4}"' in text
    assert "[ipv4-addr:value = '203.0.113.10']" in text
    assert "https://example.com/b" in text
    assert "hxxps://Example[.]COM" in text
    assert f"[file:hashes.'SHA-256' = '{HASH}']" in text
    assert "user@example.com" not in text
    assert "203.0.113.11" not in text
    assert "strict.example" not in text
    assert "red.example" not in text
    assert "AS64500" not in text
    assert "Restricted notice" not in text
    for marking_id in TLP_NOT_EXPORTED.values():
        assert marking_id not in text
    assert "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb" not in text
    assert "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421" not in text
    assert "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487" in text
    assert "password" not in text.lower()
    assert "api_key" not in text
    assert "AKIA" not in text
    report = next(item for item in bundle["objects"] if item["type"] == "report")
    vulnerability = next(item for item in bundle["objects"] if item["type"] == "vulnerability")
    assert vulnerability["id"] in report["object_refs"]
    assert vulnerability["external_references"][0]["source_name"] == "cve"
    assert vulnerability["x_cyberau_kev"]["date_added"] == "2026-01-01"
    assert vulnerability["x_cyberau_epss"]["epss"] == 0.5
    relationship = next(item for item in bundle["objects"] if item["type"] == "relationship")
    assert relationship["relationship_type"] == "related-to"
    assert relationship["source_ref"] == ipv4
    assert SDO_NAMESPACE != STIX_NAMESPACE


def test_amber_is_explicit_audited_and_round_trips(store_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_ORG_NAME", "cyber-au")
    _seed(store_path)
    with pytest.raises(ValueError):
        export_stix(max_tlp="AMBER+STRICT", store=store_path)
    with pytest.raises(ValueError):
        export_stix(max_tlp="RED", store=store_path)
    exported = export_stix(max_tlp="AMBER", store=store_path)
    again = export_stix(max_tlp="AMBER", store=store_path)
    assert exported["text"] == again["text"]
    assert exported["explicit_max_tlp"] is True
    _validate(exported["text"])
    text = exported["text"]
    assert "203.0.113.11" in text
    assert "user@example.com" in text
    assert "strict.example" not in text
    assert "red.example" not in text
    for marking_id in TLP_NOT_EXPORTED.values():
        assert marking_id not in text
    assert "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421" in text
    sighting = next(item for item in exported["bundle"]["objects"] if item["type"] == "sighting")
    assert sighting["sighting_of_ref"].startswith("indicator--")
    assert sighting["x_cyberau_source_id"] == "analyst"
    assert "checked the lab sample" in text
    assert "<<untrusted" not in text
    audit = list((store_path.parent / "audit").glob("*.jsonl"))
    assert len(audit) == 1
    event = json.loads(audit[0].read_text(encoding="utf-8").splitlines()[-1])
    assert event["event"] == "export"
    assert event["tool"] == "intel_export_stix"
    assert event["max_tlp"] == "AMBER"
    assert event["explicit_max_tlp"] is True
    assert "203.0.113" not in audit[0].read_text(encoding="utf-8")

    other = store_path.parent / "imported.sqlite"
    import_stix(exported["bundle"], path=other)
    original = [
        item for item in _indicator_keys(store_path) if item[4] in {"CLEAR", "GREEN", "AMBER"}
    ]
    assert _indicator_keys(other) == original
    restored = lookup("https://example.com/b", type="url", path=other)[0]
    assert restored["value"] == "hxxps://Example[.]COM/a/../b#x"
    assert restored["verdict"] == "malicious"
    assert restored["confidence"] == 80
    domain = lookup("clear.example", type="domain", path=other)[0]
    assert domain["verdict"] == "malicious"
    assert domain["confidence"] == 40


def test_export_path_stays_under_exports(store_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_ORG_NAME", "cyber-au")
    _seed(store_path)
    result = intel_export_stix(path="bundle.json", store=store_path)
    written = store_path.parent / "exports" / "bundle.json"
    assert written.is_file()
    assert written.read_text(encoding="utf-8") == export_stix(store=store_path)["text"]
    assert result["data"]["path"] == "exports/bundle.json"
    assert result["untrusted"] is True
    absolute = store_path.parent / "exports" / "absolute.json"
    intel_export_stix(path=str(absolute), store=store_path)
    assert absolute.is_file()
    with pytest.raises(ValueError):
        intel_export_stix(path="../outside.json", store=store_path)
    with pytest.raises(ValueError):
        intel_export_stix(path=str(store_path.parent / "outside.json"), store=store_path)
    with pytest.raises(ValueError):
        intel_export_stix(path="notes.txt", store=store_path)


def test_exports_symlink_pointing_outside_is_refused(store_path, tmp_path):
    store_path.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (store_path.parent / "exports").symlink_to(outside)
    with pytest.raises(ValueError):
        resolve_export_path("bundle.json", store_path)
    with pytest.raises(ValueError):
        export_stix(output="bundle.json", store=store_path)
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("name", ["RED", "AMBER+STRICT", "AMBER"])
def test_import_keeps_the_marking_a_bundle_carries(store_path, name):
    ref = TLP_NOT_EXPORTED.get(name) or _AMBER_REF
    observable = "ipv4-addr--11111111-1111-4111-8111-111111111111"
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "ipv4-addr",
                "id": observable,
                "spec_version": "2.1",
                "value": "203.0.113.9",
                "object_marking_refs": [ref],
            },
            {
                "type": "report",
                "id": "report--22222222-2222-4222-8222-222222222222",
                "name": "carried marking",
                "published": "2026-01-01T00:00:00Z",
                "x_cyberau_advisory_id": "ADV-MARKED-1",
                "object_marking_refs": [ref],
                "object_refs": [observable],
                "external_references": [{"source_name": "vendor", "url": "https://example.com/a"}],
            },
        ],
    }
    import_stix(bundle, path=store_path)
    indicator = next(
        item for item in lookup("203.0.113.9", path=store_path) if item["kind"] == "indicator"
    )
    assert indicator["tlp"] == name
    advisory = lookup("ADV-MARKED-1", path=store_path)[0]
    assert advisory["tlp"] == name
    assert "203.0.113.9" not in export_stix(store=store_path)["text"]


def test_import_skips_relationships_with_unknown_ends(store_path):
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "relationship",
                "x_cyberau_src_id": "indicator--missing",
                "x_cyberau_dst_id": "CVE-2024-0001",
                "x_cyberau_rel": "related-to",
            }
        ],
    }
    assert import_stix(bundle, path=store_path)["relationships"] == 0
    assert (
        open_store(store_path)
        .connection()
        .execute("SELECT COUNT(*) FROM relationships")
        .fetchone()[0]
        == 0
    )


def test_since_kinds_and_organisation(store_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_ORG_NAME", raising=False)
    home = store_path.parent / "profile"
    home.mkdir()
    (home / "config.yaml").write_text(
        "cyber_au:\n  organisation: Example Pty Ltd\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_HOME", str(home))
    upsert_indicator(
        "domain",
        "old.example",
        source="feed",
        observed_at="2026-01-01T00:00:00Z",
        raw=b"old",
        tlp="CLEAR",
        path=store_path,
    )
    upsert_indicator(
        "domain",
        "new.example",
        source="feed",
        observed_at="2026-08-01T00:00:00Z",
        raw=b"new",
        tlp="CLEAR",
        path=store_path,
    )
    upsert_vulnerability(
        "CVE-2099-2000",
        path=store_path,
        updated_at="2026-08-02T00:00:00Z",
    )
    window = export_stix(since="2026-07-01", store=store_path)
    assert "old.example" not in window["text"]
    assert "new.example" in window["text"]
    assert "Example Pty Ltd" in window["text"]
    only = export_stix(kinds=["vulnerability"], store=store_path)
    kinds = {item["type"] for item in only["bundle"]["objects"]}
    assert "vulnerability" in kinds
    assert "domain-name" not in kinds
    assert "indicator" not in kinds
    _validate(only["text"])


def test_cli_stix21_export_and_import(store_path, capsys, monkeypatch):
    monkeypatch.setenv("CYBERAU_ORG_NAME", "cyber-au")
    _seed(store_path)
    assert (
        main(
            [
                "store",
                "export",
                "--format",
                "stix21",
                "--path",
                str(store_path),
                "--output",
                "cli.json",
                "--max-tlp",
                "AMBER",
            ]
        )
        == 0
    )
    text = capsys.readouterr().out
    written = store_path.parent / "exports" / "cli.json"
    assert written.read_text(encoding="utf-8") == text
    assert json.loads(text)["type"] == "bundle"
    other = store_path.parent / "from-cli.sqlite"
    assert main(["store", "import-stix", str(written), "--path", str(other)]) == 0
    imported = json.loads(capsys.readouterr().out)
    assert imported["indicators"] >= 1
    assert (
        main(
            [
                "store",
                "export",
                "--format",
                "stix21",
                "--path",
                str(store_path),
                "--output",
                "../nope.json",
            ]
        )
        == 1
    )
    capsys.readouterr()
    assert main(["store", "export", "--format", "records", "--path", str(store_path)]) == 0
    records = json.loads(capsys.readouterr().out)
    assert records["max_tlp"] == "GREEN"
    assert records["explicit_max_tlp"] is False
