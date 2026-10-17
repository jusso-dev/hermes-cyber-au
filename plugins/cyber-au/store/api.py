"""Ingest and query API for the local threat intel store.

The database lives at ``$CYBERAU_DATA_DIR/intel.sqlite``, which is
``<profile>/plugin-data/cyber-au/intel.sqlite`` when that variable points at
the profile data directory.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable, Sequence
from pathlib import Path

from .canonical import (
    EXPORT_DEFAULT_TLP,
    INDICATOR_TYPES,
    canonical_cve,
    canonical_date,
    canonical_timestamp,
    canonical_value,
    indicator_id,
    more_restrictive,
    require_source_id,
    require_tlp,
    tlp_allows,
    utc_now,
)
from .db import TABLES, Store, close_store, open_store, upsert_fts
from .scoring import VERDICTS, score
from .text import (
    clean_untrusted,
    defuse_markers,
    indexable_text,
    unwrap_untrusted,
    wrap_untrusted,
)

KINDS = ("indicator", "advisory", "vulnerability")
_TOKEN = re.compile(r"[0-9A-Za-z]{1,128}")
_VULN_FIELDS = (
    "kev_date_added",
    "kev_due_date",
    "kev_ransomware",
    "epss",
    "epss_percentile",
    "epss_date",
    "cvss_v3",
    "cvss_v4",
    "cwe",
)
_DATE_FIELDS = {"kev_date_added", "kev_due_date", "epss_date"}
_FLOAT_FIELDS = {
    "epss": (0.0, 1.0),
    "epss_percentile": (0.0, 1.0),
    "cvss_v3": (0.0, 10.0),
    "cvss_v4": (0.0, 10.0),
}


def upsert_indicator(
    type: str,
    value: str,
    *,
    source: str,
    observed_at: str,
    raw: bytes,
    verdict: str | None = None,
    confidence: int | None = None,
    tags: Sequence[str] = (),
    tlp: str = "CLEAR",
    source_ref: str | None = None,
    note: str | None = None,
    path: str | Path | None = None,
) -> str:
    """Insert or merge one indicator observation and return its id.

    Re-ingesting the same ``(indicator, source, source_ref, raw)`` does not
    add a row. ``first_seen`` stays the earliest timestamp, ``last_seen`` the
    latest, and verdict, confidence and TLP are recomputed. ``note`` is
    stored on the observation as untrusted text.
    """
    indicator_type = type
    if indicator_type not in INDICATOR_TYPES:
        raise ValueError("unknown indicator type")
    if not isinstance(raw, bytes | bytearray):
        raise ValueError("raw must be bytes")
    value_norm = canonical_value(indicator_type, value)
    seen = canonical_timestamp(observed_at)
    marking = require_tlp(tlp)
    source_id = require_source_id(source)
    checked_verdict = _require_verdict(verdict)
    checked_confidence = _require_confidence(confidence)
    tag_list = _require_tags(tags)
    stored_tags = _stored_tags(tag_list, note, source_id)
    tags_json = json.dumps(stored_tags, ensure_ascii=False, separators=(",", ":"))
    ref = "" if source_ref is None else str(source_ref)
    if len(ref) > 500:
        raise ValueError("source_ref is too long")
    digest = hashlib.sha256(bytes(raw)).hexdigest()
    record_id = indicator_id(indicator_type, value_norm)
    original = value.strip()

    def write(store: Store) -> str:
        _ensure_source_row(store, source_id)
        conn = store.connection()
        existing = conn.execute(
            """
            SELECT id, value, first_seen, last_seen, tlp
            FROM indicators WHERE type = ? AND value_norm = ?
            """,
            (indicator_type, value_norm),
        ).fetchone()
        if existing is None:
            merged_verdict, merged_confidence = score(
                [{"verdict": checked_verdict, "confidence": checked_confidence}]
            )
            conn.execute(
                """
                INSERT INTO indicators (
                    id, type, value, value_norm, first_seen, last_seen,
                    verdict, confidence, tlp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record_id,
                    indicator_type,
                    original,
                    value_norm,
                    seen,
                    seen,
                    merged_verdict,
                    merged_confidence,
                    marking,
                ),
            )
            conn.execute(
                """
                INSERT INTO observations (
                    indicator_id, source_id, source_ref, observed_at, verdict,
                    confidence, tags, raw_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record_id,
                    source_id,
                    ref,
                    seen,
                    checked_verdict,
                    checked_confidence,
                    tags_json,
                    digest,
                ),
            )
            body = _indicator_body(
                original, value_norm, indicator_type, merged_verdict, stored_tags
            )
            upsert_fts(conn, "indicator", record_id, indicator_type, body, replace=False)
            return record_id

        conn.execute(
            """
            INSERT INTO observations (
                indicator_id, source_id, source_ref, observed_at, verdict,
                confidence, tags, raw_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(indicator_id, source_id, source_ref, raw_sha256) DO UPDATE SET
                observed_at = excluded.observed_at,
                verdict = excluded.verdict,
                confidence = excluded.confidence,
                tags = excluded.tags
            """,
            (
                existing["id"],
                source_id,
                ref,
                seen,
                checked_verdict,
                checked_confidence,
                tags_json,
                digest,
            ),
        )
        observations = [
            {"verdict": row["verdict"], "confidence": row["confidence"]}
            for row in conn.execute(
                "SELECT verdict, confidence FROM observations WHERE indicator_id = ?",
                (existing["id"],),
            )
        ]
        merged_verdict, merged_confidence = score(observations)
        first_seen = min(existing["first_seen"], seen)
        last_seen = max(existing["last_seen"], seen)
        merged_tlp = more_restrictive(existing["tlp"], marking)
        conn.execute(
            """
            UPDATE indicators
            SET first_seen = ?, last_seen = ?, verdict = ?, confidence = ?, tlp = ?
            WHERE id = ?
            """,
            (first_seen, last_seen, merged_verdict, merged_confidence, merged_tlp, existing["id"]),
        )
        extras = _observation_index_text(conn, existing["id"])
        body = _indicator_body(
            existing["value"], value_norm, indicator_type, merged_verdict, extras
        )
        upsert_fts(conn, "indicator", existing["id"], indicator_type, body)
        return existing["id"]

    return _run(path, write)


def upsert_vulnerability(cve_id: str, path: str | Path | None = None, **fields: object) -> None:
    """Insert or update one CVE row. Unknown keys are rejected.

    When ``epss`` is set, ``epss_date`` is required and one history row is
    written for that date. Repeating the same date replaces the history row.
    """
    cve = canonical_cve(cve_id)
    unknown = set(fields) - set(_VULN_FIELDS) - {"updated_at"}
    if unknown:
        raise ValueError("unknown vulnerability fields")
    normalised = {
        key: _normalise_vuln_field(key, fields[key]) for key in fields if key != "updated_at"
    }
    if "epss" in fields and fields["epss"] is not None and normalised.get("epss_date") is None:
        raise ValueError("epss_date is required when epss is set")
    updated_at = fields.get("updated_at")

    def write(store: Store) -> None:
        conn = store.connection()
        existing = conn.execute(
            "SELECT * FROM vulnerabilities WHERE cve_id = ?",
            (cve,),
        ).fetchone()
        current = {key: None for key in _VULN_FIELDS}
        if existing is not None:
            current.update({key: existing[key] for key in _VULN_FIELDS})
        current.update(normalised)
        if isinstance(updated_at, str):
            stamped = canonical_timestamp(updated_at)
        elif existing is not None:
            stamped = existing["updated_at"]
        else:
            stamped = utc_now()
        conn.execute(
            """
            INSERT INTO vulnerabilities (
                cve_id, kev_date_added, kev_due_date, kev_ransomware,
                epss, epss_percentile, epss_date, cvss_v3, cvss_v4, cwe, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                kev_date_added = excluded.kev_date_added,
                kev_due_date = excluded.kev_due_date,
                kev_ransomware = excluded.kev_ransomware,
                epss = excluded.epss,
                epss_percentile = excluded.epss_percentile,
                epss_date = excluded.epss_date,
                cvss_v3 = excluded.cvss_v3,
                cvss_v4 = excluded.cvss_v4,
                cwe = excluded.cwe,
                updated_at = excluded.updated_at
            """,
            (
                cve,
                current["kev_date_added"],
                current["kev_due_date"],
                current["kev_ransomware"],
                current["epss"],
                current["epss_percentile"],
                current["epss_date"],
                current["cvss_v3"],
                current["cvss_v4"],
                current["cwe"],
                stamped,
            ),
        )
        if "epss" in fields and current["epss"] is not None and current["epss_date"] is not None:
            conn.execute(
                """
                INSERT INTO epss_history (cve_id, date, epss, percentile)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(cve_id, date) DO UPDATE SET
                    epss = excluded.epss,
                    percentile = excluded.percentile
                """,
                (cve, current["epss_date"], current["epss"], current["epss_percentile"]),
            )
        body = " ".join(
            part
            for part in (cve, current["cwe"], current["kev_ransomware"])
            if isinstance(part, str) and part
        )
        upsert_fts(conn, "vulnerability", cve, cve, body, replace=existing is not None)

    _run(path, write)


def upsert_advisory(
    id: str,
    *,
    source: str,
    title: str,
    url: str,
    published_at: str | None,
    summary: str | None,
    content_sha256: str | None,
    path: str | Path | None = None,
) -> bool:
    """Insert or update one advisory. Returns True when the id is new."""
    advisory_id = _require_advisory_id(id)
    source_id = require_source_id(source)
    kept_title = clean_untrusted(title, max_len=500)
    if not kept_title:
        raise ValueError("advisory title is empty")
    kept_url = url.strip()
    if not kept_url or any(char.isspace() for char in kept_url) or len(kept_url) > 2000:
        raise ValueError("invalid advisory url")
    published = None if published_at is None else canonical_timestamp(published_at)
    wrapped = None if summary is None else wrap_untrusted(summary, source_id)
    digest = None if content_sha256 is None else content_sha256.strip().lower()
    if digest is not None and not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("content_sha256 must be 64 hex characters")

    def write(store: Store) -> bool:
        _ensure_source_row(store, source_id)
        conn = store.connection()
        existed = (
            conn.execute("SELECT 1 FROM advisories WHERE id = ?", (advisory_id,)).fetchone()
            is not None
        )
        if existed:
            conn.execute(
                """
                UPDATE advisories
                SET source_id = ?, title = ?, url = ?, published_at = ?,
                    summary = ?, content_sha256 = ?
                WHERE id = ?
                """,
                (source_id, kept_title, kept_url, published, wrapped, digest, advisory_id),
            )
        else:
            conn.execute(
                """
                INSERT INTO advisories (
                    id, source_id, title, url, published_at, summary,
                    content_sha256, first_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    advisory_id,
                    source_id,
                    kept_title,
                    kept_url,
                    published,
                    wrapped,
                    digest,
                    utc_now(),
                ),
            )
        index_summary = "" if summary is None else clean_untrusted(summary)
        upsert_fts(
            conn,
            "advisory",
            advisory_id,
            kept_title,
            f"{kept_title} {index_summary}".strip(),
            replace=existed,
        )
        return not existed

    return _run(path, write)


def ensure_source(
    source_id: str,
    *,
    name: str | None = None,
    licence: str | None = None,
    default_tlp: str | None = None,
    path: str | Path | None = None,
) -> None:
    """Create a source, or tighten its default TLP when one is supplied."""
    checked = require_source_id(source_id)
    marking = None if default_tlp is None else require_tlp(default_tlp)
    kept_name = checked if name is None else clean_untrusted(name, max_len=200)
    if not kept_name:
        raise ValueError("source name is empty")

    def write(store: Store) -> None:
        conn = store.connection()
        row = conn.execute(
            "SELECT name, licence, default_tlp FROM sources WHERE id = ?",
            (checked,),
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO sources (id, name, licence, default_tlp) VALUES (?, ?, ?, ?)",
                (checked, kept_name, licence, marking or "CLEAR"),
            )
        else:
            next_tlp = row["default_tlp"]
            if marking is not None:
                next_tlp = more_restrictive(row["default_tlp"], marking)
            next_name = row["name"] if name is None else kept_name
            next_licence = row["licence"] if licence is None else licence
            conn.execute(
                "UPDATE sources SET name = ?, licence = ?, default_tlp = ? WHERE id = ?",
                (next_name, next_licence, next_tlp, checked),
            )
        store.remember_source(checked)

    _run(path, write)


def ingest_kev_catalogue(
    catalog: dict,
    *,
    source: str = "cisa-kev",
    path: str | Path | None = None,
) -> int:
    """Load a CISA KEV catalogue. A second load of the same bytes adds no rows."""
    if not isinstance(catalog, dict) or not isinstance(catalog.get("vulnerabilities"), list):
        raise ValueError("KEV catalogue is missing vulnerabilities")
    released = catalog.get("dateReleased")
    updated = canonical_timestamp(released) if isinstance(released, str) else utc_now()
    source_id = require_source_id(source)
    rows = catalog["vulnerabilities"]

    def write(store: Store) -> int:
        _ensure_source_row(
            store,
            source_id,
            name="CISA KEV",
            licence="CISA Known Exploited Vulnerabilities catalogue. US Government work.",
            default_tlp="CLEAR",
        )
        for row in rows:
            if not isinstance(row, dict) or "cveID" not in row:
                raise ValueError("KEV row is missing cveID")
            cwes = row.get("cwes") or []
            if isinstance(cwes, list):
                cwe = ",".join(str(item) for item in cwes) or None
            else:
                cwe = str(cwes) or None
            upsert_vulnerability(
                str(row["cveID"]),
                path=store.path,
                kev_date_added=row.get("dateAdded"),
                kev_due_date=row.get("dueDate"),
                kev_ransomware=row.get("knownRansomwareCampaignUse"),
                cwe=cwe,
                updated_at=updated,
            )
        return len(rows)

    return _run(path, write)


def search(
    query: str,
    *,
    kinds: Sequence[str] = KINDS,
    limit: int = 20,
    since: str | None = None,
    path: str | Path | None = None,
) -> list[dict]:
    """Full-text search across indicators, advisories and vulnerabilities.

    Local search returns every TLP marking. Export is the path that withholds
    ``AMBER`` and above unless ``max_tlp`` is set.
    """
    chosen = _require_kinds(kinds)
    capped = _require_limit(limit, maximum=100)
    earliest = None if since is None else canonical_timestamp(since)
    match = _match_query(query, chosen)
    store = open_store(path)
    conn = store.connection()
    found: list[dict] = []
    seen: set[tuple[str, str]] = set()
    offset = 0
    while len(found) < capped and offset <= 5000:
        rows = conn.execute(
            """
            SELECT kind, ref FROM fts
            WHERE fts MATCH ?
            ORDER BY rank
            LIMIT ? OFFSET ?
            """,
            (match, 100, offset),
        ).fetchall()
        if not rows:
            break
        for row in rows:
            key = (row["kind"], row["ref"])
            if key in seen or row["kind"] not in chosen:
                continue
            seen.add(key)
            record = _hydrate(conn, row["kind"], row["ref"])
            if record is None:
                continue
            if earliest is not None and _record_time(record) < earliest:
                continue
            found.append(record)
            if len(found) >= capped:
                break
        offset += 100
    return found


def lookup(
    id_or_value: str,
    *,
    type: str | None = None,
    path: str | Path | None = None,
) -> list[dict]:
    """Fetch by STIX id, CVE id, advisory id, or indicator value."""
    if not isinstance(id_or_value, str) or not id_or_value.strip():
        raise ValueError("id_or_value is empty")
    store = open_store(path)
    conn = store.connection()
    matches: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(record: dict | None) -> None:
        if record is None:
            return
        key = (record["kind"], record["id"])
        if key not in seen:
            seen.add(key)
            matches.append(record)

    needle = id_or_value.strip()
    add(_hydrate(conn, "indicator", needle))
    add(_hydrate(conn, "advisory", needle))
    cve_key = canonical_cve(needle) if needle.upper().startswith("CVE-") else needle
    add(_hydrate(conn, "vulnerability", cve_key))
    if type is not None:
        if type not in INDICATOR_TYPES:
            raise ValueError("unknown indicator type")
        add(_indicator_by_norm(conn, type, canonical_value(type, needle)))
        return matches
    for candidate in INDICATOR_TYPES:
        try:
            value_norm = canonical_value(candidate, needle)
        except ValueError:
            continue
        add(_indicator_by_norm(conn, candidate, value_norm))
    return matches


def export_records(
    *,
    kinds: Sequence[str] = KINDS,
    max_tlp: str | None = None,
    path: str | Path | None = None,
) -> list[dict]:
    """Copy records out of the store.

    When ``max_tlp`` is omitted, ``AMBER`` and above stay in the store. Pass
    ``max_tlp`` to request a higher ceiling. This is not a STIX or DuckDB export.
    """
    chosen = _require_kinds(kinds)
    ceiling = EXPORT_DEFAULT_TLP if max_tlp is None else require_tlp(max_tlp)
    store = open_store(path)
    conn = store.connection()
    records: list[dict] = []
    if "indicator" in chosen:
        for row in conn.execute("SELECT * FROM indicators ORDER BY id"):
            if tlp_allows(row["tlp"], ceiling):
                records.append(_indicator_dict(row))
    if "advisory" in chosen:
        rows = conn.execute(
            """
            SELECT a.*, s.default_tlp AS tlp
            FROM advisories a
            JOIN sources s ON s.id = a.source_id
            ORDER BY a.id
            """
        )
        for row in rows:
            if tlp_allows(row["tlp"], ceiling):
                records.append(_advisory_dict(row))
    if "vulnerability" in chosen:
        for row in conn.execute("SELECT * FROM vulnerabilities ORDER BY cve_id"):
            if tlp_allows("CLEAR", ceiling):
                records.append(_vulnerability_dict(row))
    records.sort(key=lambda item: (item["kind"], item["id"]))
    return records


def table_counts(path: str | Path | None = None) -> dict[str, int]:
    store = open_store(path)
    conn = store.connection()
    return {name: conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in TABLES}


def _run(path: str | Path | None, fn: Callable[[Store], object]) -> object:
    store = open_store(path)
    if store.in_transaction():
        return fn(store)
    with store.transaction():
        return fn(store)


def _ensure_source_row(
    store: Store,
    source_id: str,
    *,
    name: str | None = None,
    licence: str | None = None,
    default_tlp: str | None = None,
) -> None:
    if name is None and licence is None and default_tlp is None and store.source_known(source_id):
        return
    conn = store.connection()
    if name is None and licence is None and default_tlp is None:
        conn.execute(
            "INSERT OR IGNORE INTO sources (id, name, default_tlp) VALUES (?, ?, 'CLEAR')",
            (source_id, source_id),
        )
        store.remember_source(source_id)
        return
    ensure_source(
        source_id,
        name=name,
        licence=licence,
        default_tlp=default_tlp,
        path=store.path,
    )


def _indicator_body(
    value: str,
    value_norm: str,
    indicator_type: str,
    verdict: str | None,
    extras: Sequence[str],
) -> str:
    parts = [value_norm, value, indicator_type]
    if verdict:
        parts.append(verdict)
    parts.extend(indexable_text(item) for item in extras if item)
    return " ".join(parts)


def _observation_index_text(conn: sqlite3.Connection, indicator: str) -> list[str]:
    texts: list[str] = []
    for row in conn.execute("SELECT tags FROM observations WHERE indicator_id = ?", (indicator,)):
        try:
            tags = json.loads(row["tags"] or "[]")
        except json.JSONDecodeError:
            continue
        if isinstance(tags, list):
            texts.extend(str(tag) for tag in tags)
    return texts


def _hydrate(conn: sqlite3.Connection, kind: str, ref: str) -> dict | None:
    if kind == "indicator":
        row = conn.execute("SELECT * FROM indicators WHERE id = ?", (ref,)).fetchone()
        if row is None:
            return None
        record = _indicator_dict(row)
        record["observations"] = _observation_dicts(conn, ref)
        return record
    if kind == "advisory":
        row = conn.execute(
            """
            SELECT a.*, s.default_tlp AS tlp
            FROM advisories a JOIN sources s ON s.id = a.source_id
            WHERE a.id = ?
            """,
            (ref,),
        ).fetchone()
        return None if row is None else _advisory_dict(row)
    if kind == "vulnerability":
        row = conn.execute("SELECT * FROM vulnerabilities WHERE cve_id = ?", (ref,)).fetchone()
        return None if row is None else _vulnerability_dict(row)
    return None


def _indicator_by_norm(
    conn: sqlite3.Connection, indicator_type: str, value_norm: str
) -> dict | None:
    row = conn.execute(
        "SELECT id FROM indicators WHERE type = ? AND value_norm = ?",
        (indicator_type, value_norm),
    ).fetchone()
    if row is None:
        return None
    return _hydrate(conn, "indicator", row["id"])


def _indicator_dict(row: sqlite3.Row) -> dict:
    return {
        "kind": "indicator",
        "id": row["id"],
        "type": row["type"],
        "value": row["value"],
        "value_norm": row["value_norm"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "verdict": row["verdict"],
        "confidence": row["confidence"],
        "tlp": row["tlp"],
    }


def _advisory_dict(row: sqlite3.Row) -> dict:
    return {
        "kind": "advisory",
        "id": row["id"],
        "source_id": row["source_id"],
        "title": row["title"],
        "url": row["url"],
        "published_at": row["published_at"],
        "summary": row["summary"],
        "content_sha256": row["content_sha256"],
        "first_seen": row["first_seen"],
        "tlp": row["tlp"],
    }


def _vulnerability_dict(row: sqlite3.Row) -> dict:
    return {
        "kind": "vulnerability",
        "id": row["cve_id"],
        "cve_id": row["cve_id"],
        "kev_date_added": row["kev_date_added"],
        "kev_due_date": row["kev_due_date"],
        "kev_ransomware": row["kev_ransomware"],
        "epss": row["epss"],
        "epss_percentile": row["epss_percentile"],
        "epss_date": row["epss_date"],
        "cvss_v3": row["cvss_v3"],
        "cvss_v4": row["cvss_v4"],
        "cwe": row["cwe"],
        "updated_at": row["updated_at"],
        "tlp": "CLEAR",
    }


def _observation_dicts(conn: sqlite3.Connection, indicator: str) -> list[dict]:
    rows = conn.execute(
        """
        SELECT source_id, source_ref, observed_at, verdict, confidence, tags
        FROM observations WHERE indicator_id = ? ORDER BY id
        """,
        (indicator,),
    )
    records = []
    for row in rows:
        try:
            parsed = json.loads(row["tags"] or "[]")
        except json.JSONDecodeError:
            parsed = []
        tags, note = _split_stored_tags(parsed)
        records.append(
            {
                "source_id": row["source_id"],
                "source_ref": row["source_ref"] or None,
                "observed_at": row["observed_at"],
                "verdict": row["verdict"],
                "confidence": row["confidence"],
                "tags": tags,
                "note": note,
            }
        )
    return records


def _stored_tags(tags: Sequence[str], note: str | None, source_id: str) -> list[str]:
    stored = list(tags)
    if note is None:
        return stored
    if not isinstance(note, str):
        raise ValueError("note must be a string")
    if clean_untrusted(note):
        stored.append(wrap_untrusted(note, source_id))
    return stored


def _split_stored_tags(tags: object) -> tuple[list[str], str | None]:
    if not isinstance(tags, list):
        return [], None
    plain: list[str] = []
    note = None
    for tag in tags:
        if not isinstance(tag, str):
            continue
        if note is None and unwrap_untrusted(tag) is not None:
            note = tag
            continue
        plain.append(tag)
    return plain, note


def _record_time(record: dict) -> str:
    if record["kind"] == "indicator":
        return record["last_seen"]
    if record["kind"] == "advisory":
        return record["published_at"] or record["first_seen"]
    return record["updated_at"]


def _match_query(query: str, kinds: tuple[str, ...]) -> str:
    if not isinstance(query, str) or not query.strip():
        raise ValueError("query is empty")
    tokens = _TOKEN.findall(query)
    if not tokens:
        raise ValueError("query has no searchable terms")
    if len(tokens) > 32:
        raise ValueError("query is too long")
    terms = " AND ".join(f'"{token}"' for token in tokens)
    if len(kinds) == len(KINDS):
        return terms
    kind_clause = " OR ".join(f'kind : "{kind}"' for kind in kinds)
    return f"({kind_clause}) AND {terms}"


def _require_kinds(kinds: Sequence[str]) -> tuple[str, ...]:
    if isinstance(kinds, str) or kinds is None:
        raise ValueError("kinds must be a list")
    chosen = tuple(kinds)
    if not chosen or any(kind not in KINDS for kind in chosen):
        raise ValueError("kinds must be indicator, advisory or vulnerability")
    return chosen


def _require_limit(limit: int, *, maximum: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > maximum:
        raise ValueError(f"limit must be an integer from 1 to {maximum}")
    return limit


def _require_verdict(verdict: str | None) -> str | None:
    if verdict is None:
        return None
    if verdict not in VERDICTS:
        raise ValueError("verdict must be malicious, suspicious, benign or unknown")
    return verdict


def _require_confidence(confidence: int | None) -> int | None:
    if confidence is None:
        return None
    if isinstance(confidence, bool) or not isinstance(confidence, int):
        raise ValueError("confidence must be an integer from 0 to 100")
    if confidence < 0 or confidence > 100:
        raise ValueError("confidence must be an integer from 0 to 100")
    return confidence


def _require_tags(tags: Sequence[str]) -> list[str]:
    if isinstance(tags, str) or tags is None:
        raise ValueError("tags must be a list")
    if len(tags) > 32:
        raise ValueError("too many tags")
    cleaned = []
    for tag in tags:
        if not isinstance(tag, str):
            raise ValueError("tags must be strings")
        text = defuse_markers(clean_untrusted(tag, max_len=200))
        if text:
            cleaned.append(text)
    return cleaned


def _require_advisory_id(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid advisory id")
    text = value.strip()
    if not text or len(text) > 200 or any(char.isspace() for char in text):
        raise ValueError("invalid advisory id")
    return text


def _normalise_vuln_field(key: str, value: object) -> object:
    if value is None:
        return None
    if key in _DATE_FIELDS:
        if not isinstance(value, str):
            raise ValueError(f"invalid {key}")
        return canonical_date(value)
    if key in _FLOAT_FIELDS:
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ValueError(f"invalid {key}")
        number = float(value)
        low, high = _FLOAT_FIELDS[key]
        if number != number or number < low or number > high:
            raise ValueError(f"invalid {key}")
        return number
    if key == "kev_ransomware":
        if not isinstance(value, str):
            raise ValueError("invalid kev_ransomware")
        text = clean_untrusted(value, max_len=40)
        return text or None
    if key == "cwe":
        if not isinstance(value, str):
            raise ValueError("invalid cwe")
        text = clean_untrusted(value, max_len=200)
        return text or None
    if key == "updated_at":
        if not isinstance(value, str):
            raise ValueError("invalid updated_at")
        return canonical_timestamp(value)
    raise ValueError("unknown vulnerability fields")


__all__ = [
    "close_store",
    "ensure_source",
    "export_records",
    "ingest_kev_catalogue",
    "lookup",
    "open_store",
    "search",
    "table_counts",
    "upsert_advisory",
    "upsert_indicator",
    "upsert_vulnerability",
]
