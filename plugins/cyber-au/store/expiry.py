"""Drop store rows that a feed no longer vouches for.

Two kinds of expiry:

- Membership. A list feed (Feodo Tracker, the KEV catalogue) is the full
  current list on every fetch. After a complete, live fetch, anything that
  source contributed and no longer lists is removed, so the store never keeps
  a C2 address or KEV flag the publisher has withdrawn.
- Age. Feed advisories, EPSS history and unlinked Feodo-only IOCs older than ``feed_retention_days``
  (``cyber_au.store.feed_retention_days``, default 180) are removed.

Only feed-sourced rows are touched. Analyst rows and other sources stay.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .canonical import canonical_cve, canonical_value
from .db import fts_rowid, open_store
from .policy import load_config, require_retention_days

DEFAULT_FEED_RETENTION_DAYS = 180
FEED_ADVISORY_SOURCES = ("asd-acsc", "auscert")


def feed_retention_days(path: Path | None = None) -> int:
    store = (load_config(path).get("cyber_au") or {}).get("store") or {}
    if not isinstance(store, dict) or "feed_retention_days" not in store:
        return DEFAULT_FEED_RETENTION_DAYS
    return require_retention_days(store["feed_retention_days"])


def reconcile_indicators(
    source_id: str,
    current: Iterable[tuple[str, str]],
    *,
    path: str | Path | None = None,
) -> int:
    """Remove ``source_id``'s evidence for indicators missing from ``current``.

    ``current`` holds ``(type, value)`` pairs from a complete live fetch.
    Indicators left with no evidence from any source are deleted. Returns how
    many indicators lost this source's evidence.
    """
    keep = {(kind, canonical_value(kind, value)) for kind, value in current}
    store = open_store(path)
    with store.transaction():
        conn = store.connection()
        rows = conn.execute(
            """
            SELECT DISTINCT i.id, i.type, i.value_norm FROM indicators i
            WHERE EXISTS (SELECT 1 FROM observations o
                          WHERE o.indicator_id = i.id AND o.source_id = ?)
               OR EXISTS (SELECT 1 FROM indicator_counters c
                          WHERE c.indicator_id = i.id AND c.source_id = ?)
            """,
            (source_id, source_id),
        ).fetchall()
        gone = [row["id"] for row in rows if (row["type"], row["value_norm"]) not in keep]
        for indicator_id in gone:
            conn.execute(
                "DELETE FROM observations WHERE indicator_id = ? AND source_id = ?",
                (indicator_id, source_id),
            )
            conn.execute(
                "DELETE FROM indicator_counters WHERE indicator_id = ? AND source_id = ?",
                (indicator_id, source_id),
            )
        _drop_orphan_indicators(conn, gone)
    return len(gone)


def reconcile_kev(current_cves: Iterable[str], *, path: str | Path | None = None) -> int:
    """Clear KEV fields for CVEs the catalogue no longer lists.

    A CVE row that only existed for KEV and EPSS is then deleted with its EPSS
    history. Returns how many CVEs lost their KEV entry.
    """
    keep = {canonical_cve(cve) for cve in current_cves}
    store = open_store(path)
    with store.transaction():
        conn = store.connection()
        listed = conn.execute(
            "SELECT cve_id FROM vulnerabilities WHERE kev_date_added IS NOT NULL"
        ).fetchall()
        gone = [row["cve_id"] for row in listed if row["cve_id"] not in keep]
        for cve in gone:
            conn.execute(
                """
                UPDATE vulnerabilities
                SET kev_date_added = NULL, kev_due_date = NULL, kev_ransomware = NULL
                WHERE cve_id = ?
                """,
                (cve,),
            )
        _drop_feed_only_vulnerabilities(conn, only=gone)
    return len(gone)


def expire_by_age(
    *,
    path: str | Path | None = None,
    now: datetime | None = None,
    days: int | None = None,
) -> dict[str, int]:
    """Delete aged feed rows, retaining shared or linked indicator evidence."""
    window = feed_retention_days() if days is None else require_retention_days(days)
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    cutoff = (moment - timedelta(days=window)).strftime("%Y-%m-%dT%H:%M:%SZ")
    store = open_store(path)
    with store.transaction():
        conn = store.connection()
        marks = ",".join("?" for _ in FEED_ADVISORY_SOURCES)
        old = conn.execute(
            f"""
            SELECT id FROM advisories
            WHERE source_id IN ({marks}) AND COALESCE(published_at, first_seen) < ?
            """,
            (*FEED_ADVISORY_SOURCES, cutoff),
        ).fetchall()
        for row in old:
            _delete_advisory(conn, row["id"])
        history = conn.execute("DELETE FROM epss_history WHERE date < ?", (cutoff[:10],)).rowcount
        _drop_feed_only_vulnerabilities(conn, before=cutoff[:10])
        # Only the built-in list feed is disposable. Any other source or a
        # relationship keeps the IOC, even when its feed evidence is old.
        indicators = [
            row[0]
            for row in conn.execute(
                """
            SELECT i.id FROM indicators i WHERE i.last_seen < ?
              AND EXISTS (SELECT 1 FROM observations o WHERE o.indicator_id = i.id
                          UNION ALL SELECT 1 FROM indicator_counters c WHERE c.indicator_id = i.id)
              AND NOT EXISTS (SELECT 1 FROM observations o WHERE o.indicator_id = i.id
                              AND o.source_id != 'feodo-tracker')
              AND NOT EXISTS (SELECT 1 FROM indicator_counters c WHERE c.indicator_id = i.id
                              AND c.source_id != 'feodo-tracker')
              AND NOT EXISTS (SELECT 1 FROM relationships r
                              WHERE r.src_id = i.id OR r.dst_id = i.id)
            """,
                (cutoff,),
            )
        ]
        for indicator_id in indicators:
            conn.execute("DELETE FROM observations WHERE indicator_id = ?", (indicator_id,))
            conn.execute("DELETE FROM indicator_counters WHERE indicator_id = ?", (indicator_id,))
        _drop_orphan_indicators(conn, indicators)
    return {"advisories": len(old), "epss_history": history, "indicators": len(indicators)}


def _delete_advisory(conn, advisory_id: str) -> None:
    conn.execute("DELETE FROM advisory_refs WHERE advisory_id = ?", (advisory_id,))
    conn.execute(
        "DELETE FROM relationships WHERE src_id = ? OR dst_id = ?", (advisory_id, advisory_id)
    )
    conn.execute("DELETE FROM fts WHERE rowid = ?", (fts_rowid("advisory", advisory_id),))
    conn.execute("DELETE FROM advisories WHERE id = ?", (advisory_id,))


def _drop_orphan_indicators(conn, candidates: list[str]) -> None:
    for indicator_id in candidates:
        evidence = conn.execute(
            """
            SELECT 1 FROM observations WHERE indicator_id = ?
            UNION ALL SELECT 1 FROM indicator_counters WHERE indicator_id = ?
            LIMIT 1
            """,
            (indicator_id, indicator_id),
        ).fetchone()
        if evidence is not None:
            continue
        conn.execute(
            "DELETE FROM relationships WHERE src_id = ? OR dst_id = ?",
            (indicator_id, indicator_id),
        )
        conn.execute("DELETE FROM fts WHERE rowid = ?", (fts_rowid("indicator", indicator_id),))
        conn.execute("DELETE FROM indicators WHERE id = ?", (indicator_id,))


def _drop_feed_only_vulnerabilities(
    conn, *, only: list[str] | None = None, before: str | None = None
) -> None:
    """Delete CVE rows kept only by KEV and EPSS: no KEV entry and no CVSS.

    ``only`` limits this to CVEs that just left KEV. ``before`` limits it to
    rows whose EPSS score is older than the feed window.
    """
    query = """
        SELECT cve_id FROM vulnerabilities
        WHERE kev_date_added IS NULL AND cvss_v3 IS NULL AND cvss_v4 IS NULL
    """
    params: tuple = ()
    if before is not None:
        query += " AND (epss_date IS NULL OR epss_date < ?)"
        params = (before,)
    selected = [row["cve_id"] for row in conn.execute(query, params).fetchall()]
    if only is not None:
        selected = [cve for cve in selected if cve in set(only)]
    for cve in selected:
        conn.execute("DELETE FROM epss_history WHERE cve_id = ?", (cve,))
        conn.execute("DELETE FROM relationships WHERE src_id = ? OR dst_id = ?", (cve, cve))
        conn.execute("DELETE FROM fts WHERE rowid = ?", (fts_rowid("vulnerability", cve),))
        conn.execute("DELETE FROM vulnerabilities WHERE cve_id = ?", (cve,))
