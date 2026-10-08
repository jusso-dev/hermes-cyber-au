"""Local keyword and hashing-vector index. Stdlib sqlite only."""

from __future__ import annotations

import json
import math
import re
import sqlite3
import struct
from pathlib import Path

from .common import DATA_BANNER

TOKEN_RE = re.compile(r"ism-\d+|[a-z0-9]{2,}")
DIM = 128


def tokenize(text: str) -> list[str]:
    return TOKEN_RE.findall((text or "").lower())


def _vector(text: str) -> list[float]:
    values = [0.0] * DIM
    for token in tokenize(text):
        digest = 0
        for char in token:
            digest = (digest * 131 + ord(char)) & 0xFFFFFFFF
        values[digest % DIM] += 1.0 if (digest >> 8) & 1 else -1.0
    norm = math.sqrt(sum(value * value for value in values)) or 1.0
    return [value / norm for value in values]


def _pack(values: list[float]) -> bytes:
    return struct.pack(f"{DIM}f", *values)


def _unpack(blob: bytes) -> list[float]:
    return list(struct.unpack(f"{DIM}f", blob))


def _cosine(left: list[float], right: list[float]) -> float:
    return sum(a * b for a, b in zip(left, right))


class Index:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("CREATE TABLE IF NOT EXISTS chunks (chunk_id TEXT PRIMARY KEY, body TEXT NOT NULL, vector BLOB NOT NULL)")
        self.db.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(chunk_id UNINDEXED, text, control_id, title, tokenize='unicode61')"
        )

    def close(self) -> None:
        self.db.close()

    def rebuild(self, chunks: list[dict]) -> int:
        self.db.execute("DELETE FROM chunks")
        self.db.execute("DELETE FROM chunks_fts")
        for chunk in chunks:
            body = json.dumps(chunk, ensure_ascii=False)
            vector = _pack(_vector(f"{chunk.get('control_id','')} {chunk.get('title','')} {chunk.get('text','')}"))
            self.db.execute(
                "INSERT INTO chunks (chunk_id, body, vector) VALUES (?, ?, ?)",
                (chunk["chunk_id"], body, vector),
            )
            self.db.execute(
                "INSERT INTO chunks_fts (chunk_id, text, control_id, title) VALUES (?, ?, ?, ?)",
                (
                    chunk["chunk_id"],
                    chunk.get("text") or "",
                    chunk.get("control_id") or "",
                    chunk.get("title") or "",
                ),
            )
        self.db.commit()
        return len(chunks)

    def get(self, chunk_id: str) -> dict | None:
        row = self.db.execute("SELECT body FROM chunks WHERE chunk_id = ?", (chunk_id,)).fetchone()
        return json.loads(row["body"]) if row else None

    def all_chunks(self) -> list[dict]:
        rows = self.db.execute("SELECT body FROM chunks").fetchall()
        return [json.loads(row["body"]) for row in rows]

    def control_ids(self) -> set[str]:
        rows = self.db.execute(
            "SELECT DISTINCT json_extract(body, '$.control_id') AS control_id FROM chunks "
            "WHERE json_extract(body, '$.control_id') IS NOT NULL "
            "AND json_extract(body, '$.control_id') != ''"
        ).fetchall()
        return {row["control_id"] for row in rows if row["control_id"]}

    def by_control(self, control_id: str, *, as_of: str | None = None) -> list[dict]:
        rows = self.db.execute(
            "SELECT body FROM chunks WHERE json_extract(body, '$.control_id') = ?",
            (control_id,),
        ).fetchall()
        chunks = [json.loads(row["body"]) for row in rows]
        return [chunk for chunk in chunks if _covers(chunk, as_of)]

    def search(self, query: str, *, limit: int = 5, as_of: str | None = None, source_id: str | None = None) -> list[dict]:
        terms = tokenize(query)
        fts_ids: list[str] = []
        if terms:
            # Quote each token so a hyphenated control id is a phrase, not an operator.
            match = " OR ".join(f'"{term}"' for term in terms[:12])
            try:
                rows = self.db.execute(
                    "SELECT chunk_id FROM chunks_fts WHERE chunks_fts MATCH ? LIMIT 40",
                    (match,),
                ).fetchall()
                fts_ids = [row["chunk_id"] for row in rows]
            except sqlite3.OperationalError:
                fts_ids = []
        if fts_ids:
            placeholders = ",".join("?" for _ in fts_ids)
            rows = self.db.execute(
                f"SELECT chunk_id, body, vector FROM chunks WHERE chunk_id IN ({placeholders})",
                fts_ids,
            ).fetchall()
        else:
            rows = self.db.execute("SELECT chunk_id, body, vector FROM chunks").fetchall()
        query_vector = _vector(query)
        ranked: list[tuple[float, dict]] = []
        for row in rows:
            chunk = json.loads(row["body"])
            if not _covers(chunk, as_of):
                continue
            if source_id and chunk.get("source_id") != source_id:
                continue
            score = _cosine(query_vector, _unpack(row["vector"]))
            if row["chunk_id"] in fts_ids:
                score += 0.15
            ranked.append((score, chunk))
        ranked.sort(key=lambda item: item[0], reverse=True)
        hits = []
        for score, chunk in ranked[:limit]:
            hits.append(_public_hit(chunk, score))
        return hits


def _covers(chunk: dict, as_of: str | None) -> bool:
    if not as_of:
        return chunk.get("valid_to") in (None, "")
    start = chunk.get("valid_from") or "0000-01-01"
    end = chunk.get("valid_to") or "9999-12-31"
    return start <= as_of <= end


def _public_hit(chunk: dict, score: float) -> dict:
    text = chunk.get("text") or ""
    return {
        "chunk_id": chunk.get("chunk_id"),
        "source_id": chunk.get("source_id"),
        "publisher": chunk.get("publisher"),
        "title": chunk.get("title"),
        "section": chunk.get("section"),
        "control_id": chunk.get("control_id") or "",
        "text": text[:4000],
        "truncated": len(text) > 4000,
        "version": chunk.get("version") or "unspecified",
        "published": chunk.get("published") or "",
        "retrieved_at": chunk.get("retrieved_at") or "",
        "url": chunk.get("url"),
        "content_sha256": chunk.get("content_sha256"),
        "applicability": chunk.get("applicability") or [],
        "essential_eight": chunk.get("essential_eight") or [],
        "valid_from": chunk.get("valid_from"),
        "valid_to": chunk.get("valid_to"),
        "evidence_class": "prepared_not_observed",
        "trust_tier_offered": chunk.get("trust_tier_offered") or "upstream_official",
        "instructions": "data_only",
        "instruction_like": bool(chunk.get("instruction_like")),
        "banner": DATA_BANNER,
        "score": round(score, 4),
    }


def open_index(path: Path, chunks: list[dict] | None = None) -> Index:
    index = Index(path)
    count = index.db.execute("SELECT COUNT(*) AS n FROM chunks").fetchone()["n"]
    if chunks is not None and (count == 0 or count != len(chunks)):
        index.rebuild(chunks)
    return index
