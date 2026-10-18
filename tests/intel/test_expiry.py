"""Expiry of feed rows the publisher no longer lists, and of aged feed rows."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from cyberau_common.cli import main
from store.api import (
    ingest_kev_catalogue,
    table_counts,
    upsert_advisory,
    upsert_indicator,
    upsert_vulnerability,
)
from store.db import open_store
from store.expiry import expire_by_age, reconcile_indicators, reconcile_kev

NOW = datetime(2026, 10, 18, tzinfo=UTC)


def _c2(value: str, source: str = "feodo-tracker", path=None) -> str:
    return upsert_indicator(
        "ipv4",
        value,
        source=source,
        observed_at="2026-10-17T00:00:00Z",
        raw=value.encode(),
        verdict="malicious",
        path=path,
    )


def _ids(store_path, table: str, column: str = "id") -> set[str]:
    conn = open_store(store_path).connection()
    return {row[0] for row in conn.execute(f"SELECT {column} FROM {table}")}


def test_withdrawn_c2_addresses_leave_the_store(store_path):
    kept = _c2("203.0.113.7", path=store_path)
    withdrawn = _c2("203.0.113.8", path=store_path)

    assert reconcile_indicators("feodo-tracker", [("ipv4", "203.0.113.7")], path=store_path) == 1

    assert _ids(store_path, "indicators") == {kept}
    assert withdrawn not in _ids(store_path, "fts", "ref")


def test_other_sources_keep_their_evidence(store_path):
    shared = _c2("203.0.113.9", path=store_path)
    _c2("203.0.113.9", source="analyst", path=store_path)

    assert reconcile_indicators("feodo-tracker", [], path=store_path) == 1

    assert _ids(store_path, "indicators") == {shared}
    sources = _ids(store_path, "observations", "source_id")
    assert sources == {"analyst"}


def test_folded_counters_are_expired_too(store_path):
    from store.maintenance import apply_retention

    _c2("203.0.113.10", path=store_path)
    apply_retention(store_path, now=NOW, days=0)
    assert table_counts(store_path)["observations"] == 0

    reconcile_indicators("feodo-tracker", [], path=store_path)

    counts = table_counts(store_path)
    assert counts["indicators"] == 0
    assert counts["indicator_counters"] == 0


def _kev(*cves: str) -> dict:
    return {
        "dateReleased": "2026-10-17T00:00:00Z",
        "vulnerabilities": [
            {"cveID": cve, "dateAdded": "2026-10-01", "cwes": ["CWE-79"]} for cve in cves
        ],
    }


def test_cves_removed_from_kev_lose_their_flag(store_path):
    ingest_kev_catalogue(_kev("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"), path=store_path)
    upsert_vulnerability(
        "CVE-2026-0002", path=store_path, epss=0.4, epss_percentile=0.9, epss_date="2026-10-17"
    )
    upsert_vulnerability("CVE-2026-0003", path=store_path, cvss_v3=9.8)

    assert reconcile_kev(["CVE-2026-0001"], path=store_path) == 2

    conn = open_store(store_path).connection()
    rows = {
        row["cve_id"]: row
        for row in conn.execute("SELECT cve_id, kev_date_added, cvss_v3 FROM vulnerabilities")
    }
    # Only KEV and EPSS kept 0002, so it goes with its EPSS history.
    assert set(rows) == {"CVE-2026-0001", "CVE-2026-0003"}
    assert rows["CVE-2026-0003"]["kev_date_added"] is None
    assert rows["CVE-2026-0003"]["cvss_v3"] == 9.8
    assert _ids(store_path, "epss_history", "cve_id") == set()


def _advisory(advisory_id: str, published: str, source: str = "asd-acsc", path=None) -> None:
    upsert_advisory(
        advisory_id,
        source=source,
        title=f"Advisory {advisory_id}",
        url=f"https://www.cyber.gov.au/{advisory_id}",
        published_at=published,
        summary="Patch now.",
        content_sha256=None,
        path=path,
    )


def test_aged_feed_advisories_and_epss_history_expire(store_path):
    _advisory("asd:old", "2026-01-01", path=store_path)
    _advisory("asd:new", "2026-10-01", path=store_path)
    _advisory("analyst:old", "2025-01-01", source="analyst", path=store_path)
    upsert_vulnerability(
        "CVE-2026-0100", path=store_path, epss=0.1, epss_percentile=0.5, epss_date="2026-01-01"
    )

    expired = expire_by_age(path=store_path, now=NOW, days=180)

    assert expired == {"advisories": 1, "epss_history": 1, "indicators": 0}
    assert _ids(store_path, "advisories") == {"asd:new", "analyst:old"}
    assert "asd:old" not in _ids(store_path, "fts", "ref")
    assert _ids(store_path, "vulnerabilities", "cve_id") == set()


def test_compact_folds_and_expires(store_path, capsys):
    _advisory("asd:ancient", "2020-01-01", path=store_path)

    assert main(["store", "compact", "--path", str(store_path)]) == 0

    out = json.loads(capsys.readouterr().out)
    assert out["expired"]["advisories"] == 1
    assert "compacted_observations" in out


def test_old_feed_only_iocs_expire_but_shared_and_linked_evidence_stays(store_path):
    from store.maintenance import apply_retention

    ids = []
    for index in range(1, 5):
        ids.append(
            upsert_indicator(
                "ipv4",
                f"203.0.113.{index}",
                source="feodo-tracker",
                observed_at="2025-01-01T00:00:00Z",
                raw=b"old",
                path=store_path,
            )
        )
    upsert_indicator(
        "ipv4",
        "203.0.113.2",
        source="analyst",
        observed_at="2025-01-01T00:00:00Z",
        raw=b"evidence",
        path=store_path,
    )
    conn = open_store(store_path).connection()
    conn.execute(
        "INSERT INTO relationships (src_id, rel, dst_id) VALUES (?, 'related', 'case:1')", (ids[2],)
    )
    upsert_indicator(
        "ipv4",
        "203.0.113.4",
        source="feodo-tracker",
        observed_at="2026-10-17T00:00:00Z",
        raw=b"fresh",
        path=store_path,
    )
    apply_retention(store_path, now=NOW, days=365)
    assert expire_by_age(path=store_path, now=NOW)["indicators"] == 1
    assert _ids(store_path, "indicators") == set(ids[1:])
    assert ids[0] not in _ids(store_path, "fts", "ref")
    assert expire_by_age(path=store_path, now=NOW)["indicators"] == 0
