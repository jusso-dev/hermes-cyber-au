"""SQLite connection, migration and full-text index for the intel store."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

_MIGRATION = Path(__file__).resolve().parent / "migrations" / "0001_init.sql"
_LOCK = threading.Lock()
_STORES: dict[str, Store] = {}

TABLES = (
    "sources",
    "indicators",
    "observations",
    "vulnerabilities",
    "epss_history",
    "advisories",
    "advisory_refs",
    "relationships",
    "routine_state",
    "fts",
)


class Store:
    """One process-local handle for an ``intel.sqlite`` file."""

    def __init__(self, path: Path):
        self.path = path
        self._local = threading.local()
        self._sources: set[str] = set()
        self._sources_lock = threading.Lock()

    def connection(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=30000")
            _enable_wal(conn)
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA cache_size=-131072")
            conn.execute("PRAGMA mmap_size=268435456")
            _migrate(conn)
            self._local.conn = conn
            self._local.depth = 0
        return conn

    def in_transaction(self) -> bool:
        return getattr(self._local, "depth", 0) > 0

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self.connection()
        depth = getattr(self._local, "depth", 0)
        if depth == 0:
            conn.execute("BEGIN IMMEDIATE")
        self._local.depth = depth + 1
        try:
            yield conn
            if depth == 0:
                conn.execute("COMMIT")
        except BaseException:
            if depth == 0:
                with suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
                with self._sources_lock:
                    self._sources.clear()
            raise
        finally:
            self._local.depth = depth

    def remember_source(self, source_id: str) -> None:
        with self._sources_lock:
            self._sources.add(source_id)

    def source_known(self, source_id: str) -> bool:
        with self._sources_lock:
            return source_id in self._sources

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None
            self._local.depth = 0


def resolve_db_path(path: str | Path | None = None) -> Path:
    """Resolve the store file.

    An explicit path wins, then ``CYBERAU_DATA_DIR/intel.sqlite``, then
    ``HERMES_HOME/plugin-data/cyber-au/intel.sqlite``. There is no shared
    ``/tmp`` default.
    """
    if path is not None and str(path).strip():
        return Path(path).expanduser().resolve()
    data_dir = os.environ.get("CYBERAU_DATA_DIR")
    if data_dir:
        return (Path(data_dir) / "intel.sqlite").expanduser().resolve()
    hermes_home = os.environ.get("HERMES_HOME")
    if hermes_home:
        return (Path(hermes_home) / "plugin-data" / "cyber-au" / "intel.sqlite").resolve()
    raise ValueError("set CYBERAU_DATA_DIR or pass a store path")


def open_store(path: str | Path | None = None) -> Store:
    resolved = str(resolve_db_path(path))
    with _LOCK:
        store = _STORES.get(resolved)
        if store is None:
            store = Store(Path(resolved))
            _STORES[resolved] = store
        return store


def close_store(path: str | Path | None = None) -> None:
    resolved = str(resolve_db_path(path))
    with _LOCK:
        store = _STORES.pop(resolved, None)
    if store is not None:
        store.close()


def fts_rowid(kind: str, ref: str) -> int:
    digest = hashlib.sha256(f"{kind}\0{ref}".encode()).digest()
    value = int.from_bytes(digest[:8], "big") & 0x7FFFFFFFFFFFFFFF
    return value or 1


def upsert_fts(
    conn: sqlite3.Connection,
    kind: str,
    ref: str,
    title: str,
    body: str,
    *,
    replace: bool = True,
) -> None:
    rowid = fts_rowid(kind, ref)
    if replace:
        conn.execute("DELETE FROM fts WHERE rowid = ?", (rowid,))
    conn.execute(
        "INSERT INTO fts(rowid, kind, ref, title, body) VALUES (?, ?, ?, ?, ?)",
        (rowid, kind, ref, title or "", body or ""),
    )


def _enable_wal(conn: sqlite3.Connection) -> None:
    """Switch to WAL. The switch needs a lock the busy timeout does not always cover."""
    deadline = time.monotonic() + 30
    while True:
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            return
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc) or time.monotonic() > deadline:
                raise
            time.sleep(0.02)


def _schema_version(conn: sqlite3.Connection) -> int:
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'"
    ).fetchone()
    if not exists:
        return 0
    return conn.execute("SELECT COALESCE(MAX(version), 0) FROM schema_version").fetchone()[0]


def _statements(script: str) -> Iterator[str]:
    """Split a migration into statements. PRAGMAs are set per connection, not here."""
    pending = ""
    for line in script.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            statement = pending.strip()
            pending = ""
            if statement and not statement.upper().startswith("PRAGMA"):
                yield statement


def _migrate(conn: sqlite3.Connection) -> None:
    """Apply the schema once, even when several processes open a new file together."""
    if _schema_version(conn) >= 1:
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        if _schema_version(conn) < 1:
            for statement in _statements(_MIGRATION.read_text(encoding="utf-8")):
                conn.execute(statement)
            conn.execute("INSERT INTO schema_version(version) VALUES (1)")
        conn.execute("COMMIT")
    except BaseException:
        with suppress(sqlite3.Error):
            conn.execute("ROLLBACK")
        raise
