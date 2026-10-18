"""DuckDB analytics export (``store export --format duckdb``)."""

from __future__ import annotations

import json
import sqlite3
import sys

import pytest
from cyberau_common.cli import main
from store.analytics import INSTALL_HINT, export_duckdb
from store.api import (
    ensure_source,
    upsert_advisory,
    upsert_indicator,
    upsert_vulnerability,
)
from store.db import TABLES, open_store


def _seed(path) -> dict[str, str]:
    ensure_source("acsc", default_tlp="CLEAR", path=path)
    ensure_source("partner", default_tlp="AMBER", keyed=True, path=path)
    clear = upsert_indicator(
        "domain",
        "clear.example",
        source="acsc",
        observed_at="2026-06-01T00:00:00Z",
        raw=b"clear",
        verdict="malicious",
        confidence=80,
        path=path,
    )
    green = upsert_indicator(
        "domain",
        "green.example",
        source="acsc",
        observed_at="2026-06-01T00:00:00Z",
        raw=b"green",
        tlp="GREEN",
        path=path,
    )
    amber = upsert_indicator(
        "domain",
        "amber.example",
        source="partner",
        observed_at="2026-06-01T00:00:00Z",
        raw=b"amber",
        tlp="AMBER",
        note="partner only",
        path=path,
    )
    upsert_vulnerability(
        "CVE-2099-0001",
        kev_date_added="2026-07-01",
        kev_ransomware="Known",
        epss=0.9,
        epss_date="2026-07-02",
        path=path,
    )
    upsert_advisory(
        "acsc:alerts:1",
        source="acsc",
        title="Public advisory",
        url="https://example.com/a",
        published_at="2026-06-02T00:00:00Z",
        summary="CVE-2099-0001",
        content_sha256=None,
        path=path,
    )
    upsert_advisory(
        "partner:1",
        source="partner",
        title="Partner advisory",
        url="https://example.com/p",
        published_at="2026-06-03T00:00:00Z",
        summary="restricted",
        content_sha256=None,
        path=path,
    )
    store = open_store(path)
    with store.transaction() as conn:
        conn.executemany(
            "INSERT INTO advisory_refs (advisory_id, ref_type, ref) VALUES (?, ?, ?)",
            [("acsc:alerts:1", "cve", "CVE-2099-0001"), ("partner:1", "cve", "CVE-2099-0001")],
        )
        conn.executemany(
            "INSERT INTO relationships (src_id, rel, dst_id) VALUES (?, ?, ?)",
            [(clear, "related-to", "CVE-2099-0001"), (amber, "related-to", clear)],
        )
        conn.execute(
            "INSERT INTO routine_state (routine, watermark, updated_at) VALUES (?, ?, ?)",
            ("daily", "2026-06-01", "2026-06-01T00:00:00Z"),
        )
    return {"clear": clear, "green": green, "amber": amber}


def _sqlite_counts(path) -> dict[str, int]:
    conn = sqlite3.connect(path)
    try:
        return {name: conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in TABLES}
    finally:
        conn.close()


def _duck_rows(path, sql):
    duckdb = pytest.importorskip("duckdb")
    con = duckdb.connect(str(path), read_only=True)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def test_round_trip_keeps_every_table_and_row_at_red(store_path):
    pytest.importorskip("duckdb")
    _seed(store_path)
    result = export_duckdb(output="all.duckdb", max_tlp="RED", store=store_path)
    written = store_path.parent / "exports" / "all.duckdb"
    assert result["output"] == "exports/all.duckdb"
    assert written.is_file()
    assert not (store_path.parent / "exports" / "all.duckdb.partial").exists()
    expected = _sqlite_counts(store_path)
    assert result["tables"] == expected
    for table, count in expected.items():
        assert _duck_rows(written, f'SELECT COUNT(*) FROM "{table}"')[0][0] == count
    vuln = _duck_rows(written, "SELECT cve_id, epss, kev_ransomware FROM vulnerabilities")
    assert vuln == [("CVE-2099-0001", 0.9, "Known")]
    keyed = _duck_rows(written, "SELECT keyed FROM sources WHERE id = 'partner'")
    assert keyed == [(1,)]
    audit = list((store_path.parent / "audit").glob("*.jsonl"))
    assert audit, "an export above GREEN is audited"
    line = json.loads(audit[0].read_text(encoding="utf-8").splitlines()[-1])
    assert line["format"] == "duckdb" and line["max_tlp"] == "RED"


def test_default_ceiling_withholds_amber_rows(store_path):
    pytest.importorskip("duckdb")
    ids = _seed(store_path)
    result = export_duckdb(output="default.duckdb", store=store_path)
    written = store_path.parent / "exports" / "default.duckdb"
    assert result["max_tlp"] == "GREEN"
    assert result["explicit_max_tlp"] is False
    assert result["omitted_above_tlp"] == {"advisories": 1, "indicators": 1}
    indicators = {row[0] for row in _duck_rows(written, "SELECT id FROM indicators")}
    assert indicators == {ids["clear"], ids["green"]}
    observed = {row[0] for row in _duck_rows(written, "SELECT indicator_id FROM observations")}
    assert ids["amber"] not in observed
    advisories = {row[0] for row in _duck_rows(written, "SELECT id FROM advisories")}
    assert advisories == {"acsc:alerts:1"}
    refs = _duck_rows(written, "SELECT advisory_id FROM advisory_refs")
    assert refs == [("acsc:alerts:1",)]
    rels = _duck_rows(written, "SELECT src_id FROM relationships")
    assert rels == [(ids["clear"],)]
    fts_refs = {row[0] for row in _duck_rows(written, "SELECT ref FROM fts")}
    assert ids["amber"] not in fts_refs and "partner:1" not in fts_refs
    text = " ".join(str(row) for row in _duck_rows(written, "SELECT * FROM fts"))
    assert "amber.example" not in text and "partner only" not in text
    assert not (store_path.parent / "audit").exists()


def test_clear_ceiling_drops_green(store_path):
    pytest.importorskip("duckdb")
    ids = _seed(store_path)
    export_duckdb(output="clear.duckdb", max_tlp="CLEAR", store=store_path)
    written = store_path.parent / "exports" / "clear.duckdb"
    assert _duck_rows(written, "SELECT id FROM indicators") == [(ids["clear"],)]


def test_export_path_is_confined_to_exports(store_path, tmp_path):
    pytest.importorskip("duckdb")
    _seed(store_path)
    for bad in ("../outside.duckdb", str(tmp_path / "outside.duckdb"), "notes.json"):
        with pytest.raises(ValueError):
            export_duckdb(output=bad, store=store_path)
    exports = store_path.parent / "exports"
    exports.mkdir(exist_ok=True)
    (exports / "link.duckdb").symlink_to(exports / "target.duckdb")
    with pytest.raises(ValueError, match="symlink"):
        export_duckdb(output="link.duckdb", store=store_path)
    (exports / "planted.duckdb.partial").symlink_to(tmp_path / "victim")
    with pytest.raises(ValueError, match="symlink"):
        export_duckdb(output="planted.duckdb", store=store_path)
    assert not (tmp_path / "victim").exists()
    assert not (tmp_path / "outside.duckdb").exists()


def test_default_output_name_is_dated(store_path):
    pytest.importorskip("duckdb")
    result = export_duckdb(store=store_path)
    assert result["output"].startswith("exports/intel-")
    assert result["output"].endswith(".duckdb")


def test_failed_export_removes_the_partial_file(store_path, monkeypatch):
    pytest.importorskip("duckdb")
    _seed(store_path)
    import store.analytics as analytics

    def boom(*args, **kwargs):
        raise RuntimeError("copy failed")

    monkeypatch.setattr(analytics, "_copy_tables", boom)
    with pytest.raises(RuntimeError):
        export_duckdb(output="broken.duckdb", store=store_path)
    exports = store_path.parent / "exports"
    assert sorted(path.name for path in exports.iterdir()) == []


def test_existing_export_is_replaced_whole(store_path):
    pytest.importorskip("duckdb")
    _seed(store_path)
    export_duckdb(output="same.duckdb", store=store_path)
    export_duckdb(output="same.duckdb", max_tlp="RED", store=store_path)
    written = store_path.parent / "exports" / "same.duckdb"
    assert _duck_rows(written, "SELECT COUNT(*) FROM indicators")[0][0] == 3


def test_cli_duckdb_export(store_path, capsys):
    pytest.importorskip("duckdb")
    _seed(store_path)
    args = ["store", "export", "--format", "duckdb", "--path", str(store_path)]
    assert main([*args, "--output", "cli.duckdb"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["output"] == "exports/cli.duckdb"
    assert payload["tables"]["indicators"] == 2
    assert main([*args, "--since", "2026-01-01"]) == 1
    assert main([*args, "--kind", "indicator"]) == 1


def test_cli_without_duckdb_names_the_extra(store_path, capsys, monkeypatch):
    monkeypatch.setitem(sys.modules, "duckdb", None)
    args = ["store", "export", "--format", "duckdb", "--path", str(store_path)]
    assert main(args) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    error = captured.err.strip()
    assert error == INSTALL_HINT
    assert "uv sync --project mcp --extra analytics" in error
    assert "\n" not in error
    assert not (store_path.parent / "exports").exists()


def test_help_lists_duckdb(capsys):
    assert main(["store", "export", "--help"]) == 0
    assert "duckdb" in capsys.readouterr().out
