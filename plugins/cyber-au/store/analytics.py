"""DuckDB analytics export for the local intel store.

DuckDB is an optional extra. Install it with
``uv sync --project mcp --extra analytics``. The default install does not
pull it in.

The export copies every store table into one ``.duckdb`` file under
``plugin-data/cyber-au/exports/``. Columns come from ``PRAGMA table_info`` so
a later migration is exported without a code change. The ``max_tlp`` ceiling
works like the record export: when it is omitted, ``AMBER`` and above stay in
the store. See ``docs/intel/duckdb.md``.
"""

from __future__ import annotations

import importlib
import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from .canonical import EXPORT_DEFAULT_TLP, TLP_RANK, require_tlp, tlp_allows, utc_now
from .db import TABLES, open_store, resolve_db_path
from .stix import _data_dir, resolve_export_path

INSTALL_HINT = (
    "DuckDB export needs the optional analytics extra: run uv sync --project mcp --extra analytics"
)
_BATCH_ROWS = 500


class DuckDBUnavailable(RuntimeError):
    """Raised when the optional ``duckdb`` package is not installed."""


def load_duckdb():
    """Import ``duckdb`` or raise :class:`DuckDBUnavailable` with the install hint."""
    try:
        return importlib.import_module("duckdb")
    except ImportError as exc:
        raise DuckDBUnavailable(INSTALL_HINT) from exc


def export_duckdb(
    *,
    output: str | None = None,
    max_tlp: str | None = None,
    store: str | Path | None = None,
) -> dict:
    """Write the store tables to a DuckDB file and return a summary."""
    duckdb = load_duckdb()
    ceiling = EXPORT_DEFAULT_TLP if max_tlp is None else require_tlp(max_tlp)
    requested = output or f"intel-{datetime.now(UTC).date().isoformat()}.duckdb"
    destination = _destination(requested, store)
    partial = destination.with_name(destination.name + ".partial")
    leftovers = (partial, partial.with_name(partial.name + ".wal"))
    for path in leftovers:
        _refuse_symlink(path)
        path.unlink(missing_ok=True)

    open_store(store).connection()  # applies pending migrations before the read
    source = resolve_db_path(store)
    src = sqlite3.connect(f"{source.as_uri()}?mode=ro", uri=True, timeout=30)
    try:
        src.execute("PRAGMA busy_timeout=30000")
        src.execute("BEGIN")  # one read transaction: every table comes from the same snapshot
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            con = duckdb.connect(str(partial))
            try:
                counts, omitted = _copy_tables(src, con, ceiling)
            finally:
                con.close()
            os.replace(partial, destination)
        except BaseException as exc:
            for path in leftovers:
                if not path.is_symlink():
                    path.unlink(missing_ok=True)
            if isinstance(exc, duckdb.Error):
                raise ValueError(f"DuckDB export failed: {exc}") from exc
            raise
    finally:
        src.close()
    relative = destination.relative_to(_data_dir(store).resolve()).as_posix()
    if TLP_RANK[ceiling] > TLP_RANK[EXPORT_DEFAULT_TLP]:
        _audit(store, ceiling, max_tlp is not None, counts, relative)
    return {
        "explicit_max_tlp": max_tlp is not None,
        "format": "duckdb",
        "max_tlp": ceiling,
        "omitted_above_tlp": omitted,
        "output": relative,
        "tables": counts,
    }


def _destination(requested: str, store: str | Path | None) -> Path:
    destination = resolve_export_path(requested, store, suffix=".duckdb")
    raw = Path(requested)
    candidate = raw if raw.is_absolute() else _data_dir(store) / "exports" / raw
    _refuse_symlink(candidate)
    return destination


def _refuse_symlink(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("refusing to write through a symlink")


def _copy_tables(
    src: sqlite3.Connection, con, ceiling: str
) -> tuple[dict[str, int], dict[str, int]]:
    withheld_indicators = {
        row[0]
        for row in src.execute("SELECT id, tlp FROM indicators")
        if not tlp_allows(row[1], ceiling)
    }
    withheld_advisories = {
        row[0]
        for row in src.execute(
            "SELECT a.id, s.default_tlp FROM advisories a JOIN sources s ON s.id = a.source_id"
        )
        if not tlp_allows(row[1], ceiling)
    }
    withheld = withheld_indicators | withheld_advisories

    def keep(table: str, row: dict) -> bool:
        if table == "indicators":
            return row["id"] not in withheld_indicators
        if table in ("observations", "indicator_counters"):
            return row["indicator_id"] not in withheld_indicators
        if table == "advisories":
            return row["id"] not in withheld_advisories
        if table == "advisory_refs":
            return row["advisory_id"] not in withheld_advisories
        if table == "relationships":
            return row["src_id"] not in withheld and row["dst_id"] not in withheld
        if table == "fts":
            return row["ref"] not in withheld
        return True

    counts: dict[str, int] = {}
    for table in TABLES:
        columns = _columns(src, table)
        names = [name for name, _ in columns]
        definition = ", ".join(f"{_quote(name)} {kind}" for name, kind in columns)
        con.execute(f"CREATE TABLE {_quote(table)} ({definition})")
        selected = ", ".join(_quote(name) for name in names)
        cursor = src.execute(f"SELECT {selected} FROM {_quote(table)}")
        written = 0
        row_marks = "(" + ", ".join("?" for _ in names) + ")"
        while True:
            fetched = cursor.fetchmany(_BATCH_ROWS)
            if not fetched:
                break
            batch = [row for row in fetched if keep(table, dict(zip(names, row, strict=True)))]
            if not batch:
                continue
            con.execute(
                f"INSERT INTO {_quote(table)} VALUES " + ", ".join(row_marks for _ in batch),
                [value for row in batch for value in row],
            )
            written += len(batch)
        counts[table] = written
    omitted = {
        "advisories": len(withheld_advisories),
        "indicators": len(withheld_indicators),
    }
    return counts, omitted


def _columns(src: sqlite3.Connection, table: str) -> list[tuple[str, str]]:
    rows = src.execute(f"PRAGMA table_info({_quote(table)})").fetchall()
    if not rows:
        raise ValueError(f"store table {table} is missing")
    return [(row[1], _duckdb_type(row[2])) for row in rows]


def _duckdb_type(declared: str) -> str:
    """Map a SQLite declared type to DuckDB using SQLite's affinity rules."""
    text = (declared or "").upper()
    if "INT" in text:
        return "BIGINT"
    if any(word in text for word in ("CHAR", "CLOB", "TEXT")) or not text:
        return "VARCHAR"
    if "BLOB" in text:
        return "BLOB"
    return "DOUBLE"


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _audit(
    store: str | Path | None,
    ceiling: str,
    explicit: bool,
    counts: dict[str, int],
    output: str,
) -> None:
    moment = utc_now()
    directory = _data_dir(store) / "audit"
    directory.mkdir(parents=True, exist_ok=True)
    record = {
        "event": "export",
        "explicit_max_tlp": explicit,
        "format": "duckdb",
        "max_tlp": ceiling,
        "output": output,
        "row_count": sum(counts.values()),
        "tool": "store_export_duckdb",
        "ts": moment,
    }
    line = json.dumps(record, ensure_ascii=False, sort_keys=True)
    with (directory / f"{moment[:10]}.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


__all__ = ["INSTALL_HINT", "DuckDBUnavailable", "export_duckdb", "load_duckdb"]
