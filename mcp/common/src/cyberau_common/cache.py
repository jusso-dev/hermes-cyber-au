"""SQLite HTTP cache. The cache key never includes a secret."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

import zstandard


@dataclass
class CachedResponse:
    key: str
    status: int
    headers: dict[str, str]
    body: bytes
    fetched_at: float
    etag: str | None
    last_modified: str | None
    ttl: int


class HttpCache:
    def __init__(
        self,
        path: Path,
        *,
        now=None,
        persistence: str = "ttl",
        ttl_max: int | None = None,
    ):
        if persistence not in {"none", "session", "ttl"}:
            raise ValueError("cache persistence must be none, session or ttl")
        self.path = path
        self.persistence = persistence
        self.ttl_max = ttl_max
        self._now = now or time.time
        self._memory: dict[str, CachedResponse] = {}
        self._compressor = zstandard.ZstdCompressor(level=3)
        self._decompressor = zstandard.ZstdDecompressor()
        if persistence != "ttl":
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS http_cache (
                    key TEXT PRIMARY KEY,
                    status INTEGER NOT NULL,
                    headers TEXT NOT NULL,
                    body BLOB NOT NULL,
                    fetched_at REAL NOT NULL,
                    etag TEXT,
                    last_modified TEXT,
                    ttl INTEGER NOT NULL
                )
                """
            )

    def key(self, method: str, url: str, params: dict | None, body: bytes, scope: str) -> str:
        payload = json.dumps(
            {
                "method": method.upper(),
                "url": url,
                "params": sorted((params or {}).items()),
                "body": hashlib.sha256(body).hexdigest(),
                "scope": scope,
            },
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def get(self, key: str) -> CachedResponse | None:
        if self.persistence == "none":
            return None
        if self.persistence == "session":
            return self._memory.get(key)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT status, headers, body, fetched_at, etag, last_modified, ttl
                FROM http_cache WHERE key = ?
                """,
                (key,),
            ).fetchone()
        if row is None:
            return None
        if self.ttl_max is not None and self._now() - row[3] >= self.ttl_max:
            # A licence cache limit is a retention limit. Serving past it, even as
            # stale-if-error or offline, would use data the terms no longer allow.
            with self._connect() as conn:
                conn.execute("DELETE FROM http_cache WHERE key = ?", (key,))
            return None
        return CachedResponse(
            key=key,
            status=row[0],
            headers=json.loads(row[1]),
            body=self._decompressor.decompress(row[2]),
            fetched_at=row[3],
            etag=row[4],
            last_modified=row[5],
            ttl=row[6],
        )

    def put(
        self,
        key: str,
        *,
        status: int,
        headers: dict[str, str],
        body: bytes,
        ttl: int,
    ) -> None:
        if self.persistence == "none":
            return
        if self.persistence == "ttl" and self.ttl_max is not None:
            ttl = min(int(ttl), int(self.ttl_max))
        kept = {
            name: value
            for name, value in headers.items()
            if name.lower() in {"content-type", "etag", "last-modified"}
        }
        if self.persistence == "session":
            self._memory[key] = CachedResponse(
                key=key,
                status=status,
                headers=kept,
                body=body,
                fetched_at=self._now(),
                etag=kept.get("etag") or kept.get("ETag"),
                last_modified=kept.get("last-modified") or kept.get("Last-Modified"),
                ttl=ttl,
            )
            return
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO http_cache
                    (key, status, headers, body, fetched_at, etag, last_modified, ttl)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    status=excluded.status,
                    headers=excluded.headers,
                    body=excluded.body,
                    fetched_at=excluded.fetched_at,
                    etag=excluded.etag,
                    last_modified=excluded.last_modified,
                    ttl=excluded.ttl
                """,
                (
                    key,
                    status,
                    json.dumps(kept),
                    self._compressor.compress(body),
                    self._now(),
                    kept.get("etag") or kept.get("ETag"),
                    kept.get("last-modified") or kept.get("Last-Modified"),
                    ttl,
                ),
            )

    def clear_session(self) -> None:
        """Drop memory-only responses. Called when a session ends."""
        self._memory.clear()

    def touch(self, key: str) -> None:
        if self.persistence == "none":
            return
        if self.persistence == "session":
            item = self._memory.get(key)
            if item is not None:
                item.fetched_at = self._now()
            return
        with self._connect() as conn:
            conn.execute(
                "UPDATE http_cache SET fetched_at = ? WHERE key = ?",
                (self._now(), key),
            )

    def fresh(self, item: CachedResponse) -> bool:
        return self._now() - item.fetched_at < item.ttl

    def within_stale(self, item: CachedResponse, stale_if_error: int) -> bool:
        age = self._now() - item.fetched_at
        return age < item.ttl + stale_if_error

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5)
