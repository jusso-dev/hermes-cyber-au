"""Three processes can write the store without corrupting it."""

from __future__ import annotations

import multiprocessing
import sqlite3

from store.api import table_counts, upsert_indicator
from store.db import close_store, open_store
from store.workers import write_distinct, write_same


def _intact(path):
    conn = sqlite3.connect(path)
    try:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert list(conn.execute("PRAGMA foreign_key_check")) == []
    finally:
        conn.close()


def _run(path, target, prefixes, count):
    open_store(path)
    close_store(path)
    ctx = multiprocessing.get_context("spawn")
    processes = []
    for prefix in prefixes:
        proc = ctx.Process(target=target, args=(str(path), prefix, count))
        proc.start()
        processes.append(proc)
    for proc in processes:
        proc.join(60)
        assert proc.exitcode == 0
    _intact(path)


def test_three_writers_insert_distinct_indicators(tmp_path):
    path = tmp_path / "distinct.sqlite"
    _run(path, write_distinct, ("a", "b", "c"), 20)
    counts = table_counts(path)
    assert counts["indicators"] == 60
    assert counts["observations"] == 60
    assert counts["sources"] == 3
    close_store(path)


def test_three_writers_share_one_indicator(tmp_path):
    path = tmp_path / "shared.sqlite"
    upsert_indicator(
        "ipv4",
        "203.0.113.10",
        source="seed",
        observed_at="2026-01-01T00:00:00Z",
        raw=b"seed",
        path=path,
    )
    close_store(path)
    _run(path, write_same, ("a", "b", "c"), 10)
    counts = table_counts(path)
    assert counts["indicators"] == 1
    assert counts["observations"] == 31
    close_store(path)
