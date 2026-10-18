"""Backup, public snapshot, retention and vacuum for the intel store."""

from __future__ import annotations

import os
import re
import sqlite3
import tempfile
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import zstandard

from .api import (
    _indicator_body,
    _observation_index_text,
    _run,
    rescore_indicator,
)
from .db import SCHEMA_VERSION, close_store, open_store, resolve_db_path, upsert_fts
from .policy import configured_zone, distribution_root, require_retention_days, retention_days
from .scoring import score
from .text import indexable_text

MAX_SNAPSHOT_BYTES = 50 * 1024 * 1024
_DAILY = re.compile(r"^intel-(\d{4}-\d{2}-\d{2})\.sqlite$")
_SOURCE_COLUMNS = ("id", "name", "licence", "default_tlp", "keyed")
_OBSERVATION_COLUMNS = (
    "id",
    "indicator_id",
    "source_id",
    "source_ref",
    "observed_at",
    "verdict",
    "confidence",
    "tags",
    "raw_sha256",
)
_COUNTER_COLUMNS = (
    "indicator_id",
    "source_id",
    "verdict",
    "observations",
    "confidence_sum",
    "first_seen",
    "last_seen",
)
_ADVISORY_COLUMNS = (
    "id",
    "source_id",
    "title",
    "url",
    "published_at",
    "summary",
    "content_sha256",
    "first_seen",
)
_VULN_COLUMNS = (
    "cve_id",
    "kev_date_added",
    "kev_due_date",
    "kev_ransomware",
    "epss",
    "epss_percentile",
    "epss_date",
    "cvss_v3",
    "cvss_v4",
    "cwe",
    "updated_at",
)
_EPSS_COLUMNS = ("cve_id", "date", "epss", "percentile")
_REF_COLUMNS = ("advisory_id", "ref_type", "ref")
_REL_COLUMNS = ("src_id", "rel", "dst_id", "source_id", "first_seen")


def apply_retention(
    path: str | Path | None = None,
    *,
    now: datetime | None = None,
    days: int | None = None,
) -> int:
    """Fold observations older than the retention window into indicator counters.

    Advisories are left in place. Returns how many observation rows were folded.
    """
    moment = _aware(now or datetime.now(UTC))
    window = retention_days() if days is None else require_retention_days(days)
    cutoff = (moment - timedelta(days=window)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def write(store) -> int:
        conn = store.connection()
        ids = conn.execute(
            "SELECT DISTINCT indicator_id FROM observations WHERE observed_at < ?",
            (cutoff,),
        ).fetchall()
        if not ids:
            return 0
        conn.execute(
            """
            INSERT INTO indicator_counters (
                indicator_id, source_id, verdict, observations, confidence_sum,
                first_seen, last_seen
            )
            SELECT
                indicator_id,
                source_id,
                COALESCE(verdict, 'unknown'),
                COUNT(*),
                SUM(COALESCE(confidence, 50)),
                MIN(observed_at),
                MAX(observed_at)
            FROM observations
            WHERE observed_at < ?
            GROUP BY indicator_id, source_id, COALESCE(verdict, 'unknown')
            ON CONFLICT(indicator_id, source_id, verdict) DO UPDATE SET
                observations = indicator_counters.observations + excluded.observations,
                confidence_sum = indicator_counters.confidence_sum + excluded.confidence_sum,
                first_seen = min(indicator_counters.first_seen, excluded.first_seen),
                last_seen = max(indicator_counters.last_seen, excluded.last_seen)
            """,
            (cutoff,),
        )
        deleted = conn.execute(
            "DELETE FROM observations WHERE observed_at < ?",
            (cutoff,),
        ).rowcount
        for row in ids:
            rescore_indicator(conn, row["indicator_id"])
        return int(deleted)

    return _run(path, write)


def backup_store(
    path: str | Path | None = None,
    *,
    now: datetime | None = None,
    keep: int = 7,
    zone: ZoneInfo | None = None,
) -> dict:
    """Online backup into ``plugin-data/cyber-au/backups`` with one file per day."""
    if isinstance(keep, bool) or not isinstance(keep, int) or keep < 1 or keep > 366:
        raise ValueError("backup keep must be an integer from 1 to 366")
    source = resolve_db_path(path)
    if not source.is_file():
        raise ValueError("store does not exist")
    moment = _aware(now or datetime.now(UTC))
    day = moment.astimezone(zone or configured_zone()).date().isoformat()
    directory = source.parent / "backups"
    _refuse_symlink(directory)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"intel-{day}.sqlite"
    partial = directory / f".intel-{day}.sqlite.partial"
    _refuse_symlink(target)
    _refuse_symlink(partial)
    try:
        if partial.exists():
            partial.unlink()
        _online_backup(source, partial)
        _integrity(partial)
        os.replace(partial, target)
    finally:
        if partial.exists():
            partial.unlink()
    _prune_backups(directory, keep)
    return {"path": str(target), "kept": keep, "date": day}


def restore_backup(backup: str | Path, path: str | Path | None = None) -> dict:
    """Replace the live store with a backup file. The backup is checked first."""
    source = Path(backup).expanduser().resolve()
    target = resolve_db_path(path)
    if not source.is_file() or source.is_symlink():
        raise ValueError("backup file is missing")
    if source == target:
        raise ValueError("backup and live store are the same file")
    _integrity(source)
    _require_intel_store(source)
    close_store(target)
    staging = target.with_name(target.name + ".restore")
    _refuse_symlink(staging)
    if staging.exists():
        staging.unlink()
    try:
        _online_backup(source, staging)
        _integrity(staging)
        _swap_in_restore(target, staging)
    finally:
        if staging.exists():
            staging.unlink()
    return {"path": str(target), "backup": str(source)}


def snapshot_public(
    path: str | Path | None = None,
    *,
    output: str | Path | None = None,
    on: date | None = None,
) -> dict:
    """Write a zstd SQLite snapshot of public-source TLP:CLEAR rows.

    Analyst observations, keyed-source rows, and every marking above CLEAR
    are omitted. Catalogue vulnerability rows are included: they have no
    keyed raw payload and are treated as CLEAR.
    """
    source = resolve_db_path(path)
    if not source.is_file():
        raise ValueError("store does not exist")
    day = on or datetime.now(UTC).date()
    if not isinstance(day, date):
        raise ValueError("invalid snapshot date")
    dest = _snapshot_destination(output, day)
    _refuse_symlink(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cyberau-snapshot-") as tmp:
        tmp_path = Path(tmp)
        full = tmp_path / "full.sqlite"
        public = tmp_path / "public.sqlite"
        _online_backup(source, full)
        _fill_public(full, public)
        _integrity(public)
        size = _compress(public, dest)
    return {"path": str(dest), "bytes": size, "date": day.isoformat()}


def vacuum_store(
    path: str | Path | None = None,
    *,
    now: datetime | None = None,
    days: int | None = None,
) -> dict:
    """Apply retention, then SQLite ``VACUUM`` so folded rows release their pages."""
    compacted = apply_retention(path, now=now, days=days)
    target = resolve_db_path(path)
    close_store(target)
    conn = sqlite3.connect(target, timeout=30, isolation_level=None)
    try:
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("VACUUM")
    finally:
        conn.close()
    return {"compacted_observations": compacted, "vacuumed": True}


def default_snapshot_dir() -> Path:
    root = distribution_root()
    base = root if root is not None else Path.cwd()
    return base / "intel" / "snapshots"


def _aware(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        raise ValueError("timestamp needs a timezone")
    return moment.astimezone(UTC).replace(microsecond=0)


def _refuse_symlink(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("refusing to write through a symlink")


def _online_backup(source: Path, dest: Path) -> None:
    if dest.exists():
        dest.unlink()
    src = sqlite3.connect(source, timeout=30)
    dst = sqlite3.connect(dest, timeout=30)
    try:
        src.execute("PRAGMA busy_timeout=30000")
        dst.execute("PRAGMA busy_timeout=30000")
        src.backup(dst)
        dst.execute("PRAGMA journal_mode=DELETE")
    finally:
        dst.close()
        src.close()


def _integrity(path: Path) -> None:
    conn = sqlite3.connect(path, timeout=30)
    try:
        row = conn.execute("PRAGMA integrity_check").fetchone()
        if row is None or row[0] != "ok":
            raise ValueError("backup failed integrity check")
    finally:
        conn.close()


def _require_intel_store(path: Path) -> None:
    """Refuse a file that is not an intel store this code can open."""
    conn = sqlite3.connect(path, timeout=30)
    try:
        tables = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        if not {"schema_version", "sources", "indicators", "observations"} <= tables:
            raise ValueError("backup is not an intel store")
        row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
        if row is None or row[0] is None or row[0] > SCHEMA_VERSION:
            raise ValueError("backup was written by a newer store schema")
    finally:
        conn.close()


def _prune_backups(directory: Path, keep: int) -> None:
    found: list[tuple[str, Path]] = []
    for path in directory.iterdir():
        match = _DAILY.fullmatch(path.name)
        if match is None or path.is_symlink() or not path.is_file():
            continue
        found.append((match.group(1), path))
    found.sort()
    for _, path in found[:-keep]:
        path.unlink()


def _swap_in_restore(target: Path, staging: Path) -> None:
    aside = target.with_name(target.name + ".aside")
    wal = Path(str(target) + "-wal")
    shm = Path(str(target) + "-shm")
    aside_wal = Path(str(aside) + "-wal")
    aside_shm = Path(str(aside) + "-shm")
    for path in (aside, aside_wal, aside_shm):
        _refuse_symlink(path)
        if path.exists():
            path.unlink()
    moved: list[tuple[Path, Path]] = []
    try:
        if target.exists():
            os.replace(target, aside)
            moved.append((aside, target))
        if wal.exists():
            os.replace(wal, aside_wal)
            moved.append((aside_wal, wal))
        if shm.exists():
            os.replace(shm, aside_shm)
            moved.append((aside_shm, shm))
        os.replace(staging, target)
    except Exception:
        for src, dest in reversed(moved):
            if src.exists() and not dest.exists():
                os.replace(src, dest)
        raise
    for leftover in (aside, aside_wal, aside_shm):
        if leftover.exists() and not leftover.is_symlink():
            leftover.unlink()


def _snapshot_destination(output: str | Path | None, day: date) -> Path:
    name = f"public-{day.isoformat()}.sqlite.zst"
    if output is None:
        return default_snapshot_dir() / name
    path = Path(output)
    if path.name.endswith(".sqlite.zst"):
        return path
    return path / name


def _fill_public(source: Path, dest: Path) -> None:
    src = sqlite3.connect(source, timeout=30)
    src.row_factory = sqlite3.Row
    store = open_store(dest)
    try:
        with store.transaction():
            _copy_public_rows(src, store.connection())
            problems = store.connection().execute("PRAGMA foreign_key_check").fetchall()
            if problems:
                raise ValueError("public snapshot failed foreign key check")
        store.connection().execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        close_store(dest)
        src.close()


def _copy_public_rows(src: sqlite3.Connection, dest: sqlite3.Connection) -> None:
    public_ids = [
        row["id"]
        for row in src.execute(
            """
            SELECT id FROM sources
            WHERE keyed = 0 AND id != 'analyst' AND default_tlp = 'CLEAR'
            """
        )
    ]
    public = set(public_ids)
    clear_indicators = {
        row["id"]: row for row in src.execute("SELECT * FROM indicators WHERE tlp = 'CLEAR'")
    }
    observations: dict[str, list[sqlite3.Row]] = {}
    counters: dict[str, list[sqlite3.Row]] = {}
    if public:
        marks = ",".join("?" for _ in public)
        keys = tuple(public)
        for row in src.execute(
            f"SELECT * FROM observations WHERE source_id IN ({marks})",
            keys,
        ):
            if row["indicator_id"] in clear_indicators and row["source_id"] != "analyst":
                observations.setdefault(row["indicator_id"], []).append(row)
        for row in src.execute(
            f"SELECT * FROM indicator_counters WHERE source_id IN ({marks})",
            keys,
        ):
            if row["indicator_id"] in clear_indicators and row["source_id"] != "analyst":
                counters.setdefault(row["indicator_id"], []).append(row)

    included: set[str] = set()
    used_sources: set[str] = set()
    kept_indicators: list[dict] = []
    for indicator_id, indicator in clear_indicators.items():
        obs = observations.get(indicator_id, [])
        folded = counters.get(indicator_id, [])
        if not obs and not folded:
            continue
        verdict, confidence, first_seen, last_seen = _rollup(obs, folded)
        kept_indicators.append(
            {
                "id": indicator["id"],
                "type": indicator["type"],
                "value": indicator["value"],
                "value_norm": indicator["value_norm"],
                "first_seen": first_seen,
                "last_seen": last_seen,
                "verdict": verdict,
                "confidence": confidence,
                "tlp": "CLEAR",
            }
        )
        included.add(indicator_id)
        used_sources.update(row["source_id"] for row in obs)
        used_sources.update(row["source_id"] for row in folded)

    advisories = []
    if public:
        marks = ",".join("?" for _ in public)
        advisories = list(
            src.execute(
                f"SELECT * FROM advisories WHERE source_id IN ({marks})",
                tuple(public),
            )
        )
        used_sources.update(row["source_id"] for row in advisories)
    included.update(row["id"] for row in advisories)

    vulnerabilities = list(src.execute("SELECT * FROM vulnerabilities"))
    included.update(row["cve_id"] for row in vulnerabilities)

    if used_sources:
        marks = ",".join("?" for _ in used_sources)
        for row in src.execute(
            f"SELECT * FROM sources WHERE id IN ({marks})",
            tuple(used_sources),
        ):
            _insert(dest, "sources", _SOURCE_COLUMNS, row)
    for mapping in kept_indicators:
        _insert(
            dest,
            "indicators",
            (
                "id",
                "type",
                "value",
                "value_norm",
                "first_seen",
                "last_seen",
                "verdict",
                "confidence",
                "tlp",
            ),
            mapping,
        )
    for rows in observations.values():
        for row in rows:
            if row["indicator_id"] in included:
                _insert(dest, "observations", _OBSERVATION_COLUMNS, row)
    for rows in counters.values():
        for row in rows:
            if row["indicator_id"] in included:
                _insert(dest, "indicator_counters", _COUNTER_COLUMNS, row)
    for row in vulnerabilities:
        _insert(dest, "vulnerabilities", _VULN_COLUMNS, row)
    for row in src.execute("SELECT * FROM epss_history"):
        if row["cve_id"] in included:
            _insert(dest, "epss_history", _EPSS_COLUMNS, row)
    for row in advisories:
        _insert(dest, "advisories", _ADVISORY_COLUMNS, row)
    advisory_ids = {row["id"] for row in advisories}
    for row in src.execute("SELECT * FROM advisory_refs"):
        if row["advisory_id"] in advisory_ids:
            _insert(dest, "advisory_refs", _REF_COLUMNS, row)
    for row in src.execute("SELECT * FROM relationships"):
        source_id = row["source_id"]
        if source_id not in public:
            continue
        if row["src_id"] in included and row["dst_id"] in included:
            _insert(dest, "relationships", _REL_COLUMNS, row)
    _rebuild_fts(dest)


def _rollup(observations: list, counters: list) -> tuple[str, int, str, str]:
    verdict, confidence = score(
        [{"verdict": row["verdict"], "confidence": row["confidence"]} for row in observations],
        [
            {
                "verdict": row["verdict"],
                "observations": row["observations"],
                "confidence_sum": row["confidence_sum"],
            }
            for row in counters
        ],
    )
    times = [row["observed_at"] for row in observations]
    times.extend(row["first_seen"] for row in counters)
    times.extend(row["last_seen"] for row in counters)
    return verdict, confidence, min(times), max(times)


def _rebuild_fts(conn: sqlite3.Connection) -> None:
    for row in conn.execute("SELECT id, type, value, value_norm, verdict FROM indicators"):
        extras = _observation_index_text(conn, row["id"])
        body = _indicator_body(row["value"], row["value_norm"], row["type"], row["verdict"], extras)
        upsert_fts(conn, "indicator", row["id"], row["type"], body, replace=False)
    for row in conn.execute("SELECT id, title, summary FROM advisories"):
        summary = indexable_text(row["summary"] or "")
        upsert_fts(
            conn,
            "advisory",
            row["id"],
            row["title"],
            f"{row['title']} {summary}".strip(),
            replace=False,
        )
    for row in conn.execute("SELECT cve_id, cwe, kev_ransomware FROM vulnerabilities"):
        body = " ".join(
            part
            for part in (row["cve_id"], row["cwe"], row["kev_ransomware"])
            if isinstance(part, str) and part
        )
        upsert_fts(conn, "vulnerability", row["cve_id"], row["cve_id"], body, replace=False)


def _insert(conn: sqlite3.Connection, table: str, columns: tuple[str, ...], row) -> None:
    names = ", ".join(columns)
    marks = ", ".join("?" for _ in columns)
    conn.execute(
        f"INSERT INTO {table} ({names}) VALUES ({marks})",
        tuple(row[name] for name in columns),
    )


def _compress(src: Path, dest: Path) -> int:
    partial = dest.with_name(dest.name + ".partial")
    _refuse_symlink(partial)
    compressor = zstandard.ZstdCompressor(level=10)
    try:
        with (
            src.open("rb") as raw,
            partial.open("wb") as out,
            compressor.stream_writer(out) as writer,
        ):
            while True:
                chunk = raw.read(1024 * 1024)
                if not chunk:
                    break
                writer.write(chunk)
        size = partial.stat().st_size
        if size >= MAX_SNAPSHOT_BYTES:
            raise ValueError("public snapshot is 50 MB or larger")
        os.replace(partial, dest)
        return size
    finally:
        if partial.exists():
            partial.unlink()
