"""Retention, online backup, restore and public TLP:CLEAR snapshots."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
import zstandard
from cyberau_common.cli import main
from store.api import (
    ensure_source,
    ingest_kev_catalogue,
    lookup,
    search,
    upsert_advisory,
    upsert_indicator,
    upsert_vulnerability,
)
from store.db import SCHEMA_VERSION, close_store, open_store
from store.maintenance import (
    MAX_SNAPSHOT_BYTES,
    apply_retention,
    backup_store,
    restore_backup,
    snapshot_public,
)
from store.policy import retention_days
from store.tools import intel_add_observation

# Fixture marker only. It is not a credential, and it must not appear in a snapshot.
KEYED_RAW = "keyed-raw-sentinel"
ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 17, tzinfo=UTC)
CATALOGUE = {
    "dateReleased": "2026-01-02T03:04:05Z",
    "vulnerabilities": [
        {
            "cveID": "CVE-2099-1111",
            "dateAdded": "2026-01-01",
            "dueDate": "2026-01-15",
            "knownRansomwareCampaignUse": "Unknown",
            "cwes": ["CWE-79"],
        }
    ],
}


def _indicator(path, **kwargs):
    fields = {
        "source": "cisa-kev",
        "observed_at": "2026-06-01T00:00:00Z",
        "raw": b"public-row",
        "verdict": "malicious",
        "confidence": 80,
        "tlp": "CLEAR",
        "path": path,
    }
    fields.update(kwargs)
    return upsert_indicator("domain", fields.pop("value"), **fields)


def test_retention_folds_old_observations_and_keeps_advisories(store_path):
    _indicator(
        store_path,
        value="scored.example",
        observed_at="2026-01-01T00:00:00Z",
        tags=["zzancienttoken"],
    )
    _indicator(
        store_path,
        value="scored.example",
        observed_at="2026-10-01T00:00:00Z",
        raw=b"recent-row",
        verdict="benign",
        tags=["zzfreshtoken"],
    )
    before = lookup("scored.example", type="domain", path=store_path)[0]
    assert before["verdict"] == "malicious"
    assert before["confidence"] == 40

    upsert_advisory(
        "adv-kept",
        source="cisa-kev",
        title="Keep this advisory",
        url="https://example.com/kept",
        published_at="2020-01-01T00:00:00Z",
        summary="still here",
        content_sha256=None,
        path=store_path,
    )
    conn = open_store(store_path).connection()
    conn.execute(
        "UPDATE advisories SET first_seen = ? WHERE id = ?",
        ("2020-01-01T00:00:00Z", "adv-kept"),
    )

    folded = apply_retention(store_path, now=NOW, days=30)
    assert folded == 1
    assert apply_retention(store_path, now=NOW, days=30) == 0

    record = lookup("scored.example", type="domain", path=store_path)[0]
    assert record["verdict"] == "malicious"
    assert record["confidence"] == 40
    assert record["first_seen"] == "2026-01-01T00:00:00Z"
    assert [row["source_id"] for row in record["observations"]] == ["cisa-kev"]
    assert record["observations"][0]["observed_at"] == "2026-10-01T00:00:00Z"
    counter = record["counters"][0]
    assert counter["observations"] == 1
    assert counter["confidence_sum"] == 80
    assert counter["verdict"] == "malicious"
    assert lookup("adv-kept", path=store_path)[0]["title"] == "Keep this advisory"
    assert search("zzancienttoken", path=store_path) == []
    assert search("zzfreshtoken", path=store_path)

    upsert_indicator(
        "domain",
        "scored.example",
        source="cisa-kev",
        observed_at="2026-10-02T00:00:00Z",
        raw=b"later-row",
        verdict="benign",
        confidence=90,
        path=store_path,
    )
    after = lookup("scored.example", type="domain", path=store_path)[0]
    assert after["verdict"] == "benign"
    assert after["confidence"] == 58


def test_repo_config_defaults_retention_to_365_days(monkeypatch, tmp_path):
    monkeypatch.delenv("CYBERAU_CONFIG", raising=False)
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.delenv("CYBERAU_HOME", raising=False)
    assert "retention_days: 365" in (ROOT / "config.yaml").read_text(encoding="utf-8")
    assert retention_days() == 365

    config = tmp_path / "config.yaml"
    config.write_text("cyber_au:\n  store:\n    retention_days: 10\n", encoding="utf-8")
    monkeypatch.setenv("CYBERAU_CONFIG", str(config))
    assert retention_days() == 10
    config.write_text("cyber_au:\n  store:\n    retention_days: -1\n", encoding="utf-8")
    try:
        retention_days()
    except ValueError as exc:
        assert "retention_days" in str(exc)
    else:
        raise AssertionError("negative retention should fail")


def test_keyed_source_cannot_be_marked_public(store_path):
    ensure_source("otx", keyed=True, path=store_path)
    try:
        ensure_source("otx", keyed=False, path=store_path)
    except ValueError as exc:
        assert "stays keyed" in str(exc)
    else:
        raise AssertionError("keyed flag should stick")


def test_backup_keeps_seven_daily_copies_and_replaces_the_same_day(store_path):
    _indicator(store_path, value="kept.example")
    open_store(store_path).connection()
    zone = ZoneInfo("UTC")
    start = datetime(2026, 1, 1, tzinfo=UTC)
    for offset in range(8):
        backup_store(store_path, now=start + timedelta(days=offset), keep=7, zone=zone)
    names = sorted(path.name for path in (store_path.parent / "backups").glob("intel-*.sqlite"))
    assert names == [f"intel-2026-01-{day:02d}.sqlite" for day in range(2, 9)]

    _indicator(store_path, value="later.example", raw=b"later")
    same_morning = backup_store(store_path, now=datetime(2026, 5, 5, 1, tzinfo=UTC), zone=zone)
    _indicator(store_path, value="evening.example", raw=b"evening")
    same_evening = backup_store(store_path, now=datetime(2026, 5, 5, 20, tzinfo=UTC), zone=zone)
    assert same_morning["path"] == same_evening["path"]
    assert same_evening["kept"] == 7
    copied = sqlite3.connect(same_evening["path"])
    try:
        values = {row[0] for row in copied.execute("SELECT value_norm FROM indicators")}
    finally:
        copied.close()
    assert "evening.example" in values
    assert copied_ok(same_evening["path"])


def test_restore_from_backup_puts_the_earlier_store_back(store_path):
    _indicator(store_path, value="kept.example")
    saved = backup_store(store_path, now=datetime(2026, 5, 1, tzinfo=UTC), zone=ZoneInfo("UTC"))
    _indicator(store_path, value="after.example", raw=b"after")
    restored = restore_backup(saved["path"], store_path)
    assert restored["path"] == str(store_path.resolve())
    assert copied_ok(store_path)
    assert lookup("kept.example", type="domain", path=store_path)
    assert lookup("after.example", type="domain", path=store_path) == []


def test_restore_refuses_a_file_that_is_not_an_intel_store(store_path, tmp_path):
    _indicator(store_path, value="live.example")
    foreign = tmp_path / "foreign.sqlite"
    conn = sqlite3.connect(foreign)
    conn.execute("CREATE TABLE t (x)")
    conn.commit()
    conn.close()
    with pytest.raises(ValueError, match="not an intel store"):
        restore_backup(foreign, store_path)
    assert lookup("live.example", type="domain", path=store_path)


def test_restore_refuses_a_newer_schema(store_path, tmp_path):
    _indicator(store_path, value="live.example")
    saved = backup_store(store_path, now=NOW, zone=ZoneInfo("UTC"))
    conn = sqlite3.connect(saved["path"])
    conn.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION + 1,))
    conn.commit()
    conn.close()
    with pytest.raises(ValueError, match="newer store schema"):
        restore_backup(saved["path"], store_path)
    assert lookup("live.example", type="domain", path=store_path)


def test_reingesting_a_folded_record_does_not_count_it_twice(store_path):
    record = {"value": "rolling.example", "observed_at": "2026-01-01T00:00:00Z", "raw": b"old"}
    _indicator(store_path, **record)
    assert apply_retention(store_path, now=NOW, days=30) == 1
    _indicator(store_path, **record)
    assert apply_retention(store_path, now=NOW, days=30) == 0
    counter = lookup("rolling.example", type="domain", path=store_path)[0]["counters"][0]
    assert counter["observations"] == 1
    assert counter["confidence_sum"] == 80


def test_a_new_record_outside_the_folded_span_still_counts(store_path):
    _indicator(store_path, value="rolling.example", observed_at="2026-01-01T00:00:00Z")
    apply_retention(store_path, now=NOW, days=30)
    _indicator(
        store_path,
        value="rolling.example",
        observed_at="2026-02-01T00:00:00Z",
        raw=b"later",
    )
    assert apply_retention(store_path, now=NOW, days=30) == 1
    counter = lookup("rolling.example", type="domain", path=store_path)[0]["counters"][0]
    assert counter["observations"] == 2


def test_cli_restore_and_snapshot_commands(store_path, capsys, tmp_path, monkeypatch):
    config = tmp_path / "config.yaml"
    config.write_text(
        "timezone: UTC\ncyber_au:\n  store:\n    retention_days: 365\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_CONFIG", str(config))
    assert main(["store", "snapshot", "--path", str(store_path)]) == 2
    _indicator(store_path, value="kept.example")
    assert main(["store", "backup", "--path", str(store_path)]) == 0
    saved = json.loads(capsys.readouterr().out)
    _indicator(store_path, value="after.example", raw=b"after")
    assert main(["store", "backup", "--restore", saved["path"], "--path", str(store_path)]) == 0
    capsys.readouterr()
    assert lookup("kept.example", type="domain", path=store_path)
    assert lookup("after.example", type="domain", path=store_path) == []

    out = tmp_path / "snaps"
    assert (
        main(
            [
                "store",
                "snapshot",
                "--public",
                "--path",
                str(store_path),
                "--output",
                str(out),
                "--date",
                "2026-04-01",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert Path(payload["path"]) == out / "public-2026-04-01.sqlite.zst"
    assert payload["bytes"] < MAX_SNAPSHOT_BYTES
    assert main(["store", "vacuum", "--path", str(store_path)]) == 0
    assert json.loads(capsys.readouterr().out)["vacuumed"] is True


def test_public_snapshot_omits_analyst_and_keyed_raw_data(store_path, tmp_path):
    ensure_source("cisa-kev", name="CISA KEV", default_tlp="CLEAR", path=store_path)
    ensure_source("community", name="Community", default_tlp="GREEN", path=store_path)
    ensure_source(
        "otx",
        name="OTX",
        default_tlp="CLEAR",
        keyed=True,
        licence=KEYED_RAW,
        path=store_path,
    )
    _indicator(store_path, value="public.example")
    _indicator(
        store_path,
        value="green.example",
        tlp="GREEN",
        raw=b"green",
        tags=["green-only-marker"],
    )
    _indicator(store_path, value="amber.example", tlp="AMBER", raw=b"amber", note=KEYED_RAW)
    _indicator(
        store_path,
        value="raised.example",
        raw=b"raised",
    )
    intel_add_observation(
        "domain",
        "raised.example",
        note=KEYED_RAW,
        path=store_path,
    )
    intel_add_observation("domain", "analyst.example", note=KEYED_RAW, path=store_path)
    upsert_indicator(
        "domain",
        "keyed.example",
        source="otx",
        observed_at="2020-01-01T00:00:00Z",
        raw=KEYED_RAW.encode(),
        tlp="CLEAR",
        note=KEYED_RAW,
        tags=[KEYED_RAW],
        source_ref=f"ref-{KEYED_RAW}",
        path=store_path,
    )
    _indicator(store_path, value="shared.example", observed_at="2026-06-01T00:00:00Z")
    upsert_indicator(
        "domain",
        "shared.example",
        source="otx",
        observed_at="2020-01-01T00:00:00Z",
        raw=b"keyed-vote",
        tlp="CLEAR",
        verdict="benign",
        confidence=80,
        note=KEYED_RAW,
        path=store_path,
    )
    _indicator(
        store_path,
        value="counted.example",
        observed_at="2020-01-01T00:00:00Z",
        raw=b"old-public",
    )
    upsert_advisory(
        "adv-public",
        source="cisa-kev",
        title="Public advisory",
        url="https://example.com/public",
        published_at="2026-06-01T00:00:00Z",
        summary="public text",
        content_sha256=None,
        path=store_path,
    )
    upsert_advisory(
        "adv-keyed",
        source="otx",
        title=KEYED_RAW,
        url="https://example.com/keyed",
        published_at="2026-06-01T00:00:00Z",
        summary=KEYED_RAW,
        content_sha256=None,
        path=store_path,
    )
    upsert_advisory(
        "adv-green",
        source="community",
        title="green-only-marker",
        url="https://example.com/green",
        published_at="2026-06-01T00:00:00Z",
        summary="green body",
        content_sha256=None,
        path=store_path,
    )
    ingest_kev_catalogue(CATALOGUE, path=store_path)
    upsert_vulnerability(
        "CVE-2099-2222",
        path=store_path,
        epss=0.5,
        epss_percentile=0.4,
        epss_date="2026-06-01",
        updated_at="2026-06-01T00:00:00Z",
    )
    apply_retention(store_path, now=NOW, days=365)

    out = tmp_path / "snaps"
    written = snapshot_public(store_path, output=out, on=NOW.date())
    snapshot = Path(written["path"])
    assert snapshot.name == "public-2026-10-17.sqlite.zst"
    assert written["bytes"] < MAX_SNAPSHOT_BYTES
    assert snapshot.stat().st_size < MAX_SNAPSHOT_BYTES

    with snapshot.open("rb") as raw, zstandard.ZstdDecompressor().stream_reader(raw) as reader:
        plain = reader.read()
    assert KEYED_RAW.encode() not in plain
    db_path = tmp_path / "public.sqlite"
    db_path.write_bytes(plain)
    conn = sqlite3.connect(db_path)
    try:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert list(conn.execute("PRAGMA foreign_key_check")) == []
        sources = {row[0] for row in conn.execute("SELECT id FROM sources")}
        assert "cisa-kev" in sources
        assert "analyst" not in sources
        assert "otx" not in sources
        assert "community" not in sources
        values = {row[0] for row in conn.execute("SELECT value_norm FROM indicators")}
        assert "public.example" in values
        assert "shared.example" in values
        assert "counted.example" in values
        assert "green.example" not in values
        assert "amber.example" not in values
        assert "raised.example" not in values
        assert "analyst.example" not in values
        assert "keyed.example" not in values
        markings = {row[0] for row in conn.execute("SELECT tlp FROM indicators")}
        assert markings <= {"CLEAR"}
        hidden = conn.execute(
            "SELECT COUNT(*) FROM observations WHERE source_id IN ('analyst', 'otx')"
        ).fetchone()[0]
        assert hidden == 0
        shared = conn.execute(
            """
            SELECT o.source_id, i.first_seen, i.confidence
            FROM indicators i
            JOIN observations o ON o.indicator_id = i.id
            WHERE i.value_norm = 'shared.example'
            """
        ).fetchall()
        assert shared == [("cisa-kev", "2026-06-01T00:00:00Z", 80)]
        counted = conn.execute(
            """
            SELECT c.observations, c.source_id
            FROM indicator_counters c
            JOIN indicators i ON i.id = c.indicator_id
            WHERE i.value_norm = 'counted.example'
            """
        ).fetchone()
        assert counted == (1, "cisa-kev")
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM observations o JOIN indicators i ON i.id = o.indicator_id "
                "WHERE i.value_norm = 'counted.example'"
            ).fetchone()[0]
            == 0
        )
        titles = {row[0] for row in conn.execute("SELECT title FROM advisories")}
        assert titles == {"Public advisory"}
        cves = {row[0] for row in conn.execute("SELECT cve_id FROM vulnerabilities")}
        assert "CVE-2099-1111" in cves
        assert conn.execute("SELECT COUNT(*) FROM epss_history").fetchone()[0] == 1
        bodies = " ".join(row[0] or "" for row in conn.execute("SELECT body FROM fts"))
        assert KEYED_RAW not in bodies
        assert "green-only-marker" not in bodies
    finally:
        conn.close()


def test_snapshot_refuses_a_file_at_the_size_limit(store_path, monkeypatch, tmp_path):
    _indicator(store_path, value="public.example")
    monkeypatch.setattr("store.maintenance.MAX_SNAPSHOT_BYTES", 1)
    try:
        snapshot_public(store_path, output=tmp_path, on=NOW.date())
    except ValueError as exc:
        assert "50 MB" in str(exc)
    else:
        raise AssertionError("oversized snapshot should fail")
    assert list(tmp_path.glob("*.zst")) == []
    assert list(tmp_path.glob("*.partial")) == []


def test_weekly_script_backs_up_and_vacuums(store_path, tmp_path, monkeypatch):
    config = tmp_path / "config.yaml"
    config.write_text(
        "timezone: UTC\ncyber_au:\n  store:\n    retention_days: 365\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_CONFIG", str(config))
    _indicator(store_path, value="kept.example")
    close_store(store_path)
    script = ROOT / "scripts" / "cyberau_store_vacuum.sh"
    completed = subprocess.run(
        ["sh", str(script)],
        env=os.environ.copy(),
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    backups = list((store_path.parent / "backups").glob("intel-*.sqlite"))
    assert len(backups) == 1
    assert copied_ok(backups[0])
    assert "kept.example" in completed.stdout or copied_has(backups[0], "kept.example")


def copied_ok(path) -> bool:
    conn = sqlite3.connect(path)
    try:
        return conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        conn.close()


def copied_has(path, value: str) -> bool:
    conn = sqlite3.connect(path)
    try:
        row = conn.execute(
            "SELECT 1 FROM indicators WHERE value_norm = ?",
            (value,),
        ).fetchone()
        return row is not None
    finally:
        conn.close()
