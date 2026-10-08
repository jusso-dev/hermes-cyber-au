"""Load citation-tagged chunks. The jsonl files are the source of truth."""

from __future__ import annotations

import json
from pathlib import Path

from .common import parse_day, repo_root


def snapshots_root(root: Path | None = None) -> Path:
    return (root or repo_root()) / "knowledge" / "snapshots"


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
    path.write_text(body, encoding="utf-8")


def load_corpus(root: Path | None = None) -> "Corpus":
    base = snapshots_root(root)
    chunks: list[dict] = []
    headers: dict[str, dict] = {}
    if base.exists():
        for path in sorted(base.glob("*/chunks.jsonl")):
            chunks.extend(_read_jsonl(path))
        for path in sorted(base.glob("*/header.json")):
            headers[path.parent.name] = json.loads(path.read_text(encoding="utf-8"))
    return Corpus(chunks, headers)


class Corpus:
    def __init__(self, chunks: list[dict], headers: dict | None = None):
        self.chunks = chunks
        self.headers = headers or {}

    def catalogue_ids(self) -> set[str]:
        return {chunk["control_id"] for chunk in self.chunks if chunk.get("control_id")}

    def by_control(self, control_id: str, *, as_of: str | None = None) -> list[dict]:
        found = [chunk for chunk in self.chunks if chunk.get("control_id") == control_id and _covers(chunk, as_of)]
        found.sort(key=lambda chunk: chunk.get("valid_from") or "")
        return found

    def current_ism(self) -> list[dict]:
        return [
            chunk
            for chunk in self.chunks
            if chunk.get("source_id") == "asd-ism-oscal" and _covers(chunk, None)
        ]

    def ism_version(self, version: str) -> list[dict]:
        return [
            chunk
            for chunk in self.chunks
            if chunk.get("source_id") == "asd-ism-oscal" and chunk.get("version") == version
        ]


def _covers(chunk: dict, as_of: str | None) -> bool:
    if not as_of:
        return chunk.get("valid_to") in (None, "")
    start = parse_day(str(chunk.get("valid_from") or "0000-01-01")) or "0000-01-01"
    end = parse_day(str(chunk.get("valid_to") or "9999-12-31")) or "9999-12-31"
    day = parse_day(as_of)
    return bool(day) and start <= day <= end
