"""SQLite rate limiter shared by every MCP process for one profile."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path


class RateLimited(Exception):
    """Raised when a request would wait longer than the timeout."""


class RateLimiter:
    def __init__(self, path: Path, *, clock=None, sleeper=None):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock or time.monotonic
        self._sleep = sleeper or time.sleep
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rolling (
                    key TEXT NOT NULL,
                    ts REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS bucket (
                    key TEXT PRIMARY KEY,
                    tokens REAL NOT NULL,
                    updated REAL NOT NULL
                )
                """
            )

    def acquire(
        self,
        key: str,
        *,
        rate: float,
        burst: int,
        window: str = "rolling",
        timeout: float = 60.0,
    ) -> None:
        if rate <= 0 or burst < 1:
            raise ValueError("rate and burst must be positive")
        if window not in {"rolling", "bucket"}:
            raise ValueError(f"unknown window: {window}")
        deadline = self._clock() + timeout
        while True:
            wait = self._reserve(key, rate=rate, burst=burst, window=window)
            if wait <= 0:
                return
            if self._clock() + wait > deadline:
                raise RateLimited(key)
            self._sleep(wait)

    def _reserve(self, key: str, *, rate: float, burst: int, window: str) -> float:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            if window == "rolling":
                wait = self._rolling(conn, key, rate=rate, burst=burst)
            else:
                wait = self._bucket(conn, key, rate=rate, burst=burst)
            conn.execute("COMMIT")
            return wait
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def _rolling(self, conn: sqlite3.Connection, key: str, *, rate: float, burst: int) -> float:
        now = self._clock()
        span = burst / rate
        conn.execute("DELETE FROM rolling WHERE key = ? AND ts <= ?", (key, now - span))
        rows = conn.execute(
            "SELECT ts FROM rolling WHERE key = ? ORDER BY ts",
            (key,),
        ).fetchall()
        if len(rows) >= burst:
            return rows[0][0] + span - now
        conn.execute("INSERT INTO rolling (key, ts) VALUES (?, ?)", (key, now))
        return 0.0

    def _bucket(self, conn: sqlite3.Connection, key: str, *, rate: float, burst: int) -> float:
        now = self._clock()
        row = conn.execute(
            "SELECT tokens, updated FROM bucket WHERE key = ?",
            (key,),
        ).fetchone()
        if row is None:
            tokens, updated = float(burst), now
        else:
            tokens, updated = row
            tokens = min(float(burst), tokens + max(0.0, now - updated) * rate)
        if tokens >= 1:
            conn.execute(
                """
                INSERT INTO bucket (key, tokens, updated) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET tokens=excluded.tokens, updated=excluded.updated
                """,
                (key, tokens - 1, now),
            )
            return 0.0
        return (1 - tokens) / rate

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        return conn
