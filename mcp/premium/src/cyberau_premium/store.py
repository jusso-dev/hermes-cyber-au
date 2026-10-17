"""Exposures table. Metadata store drops credential values."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta

from cyberau_premium.base import (
    ExposureFinding,
    TermsProfile,
    Watchlist,
    canonical_finding,
    clamp_to_terms,
)
from cyberau_premium.redact import redact_obj, redact_text

SCHEMA = """
CREATE TABLE IF NOT EXISTS exposures (
  finding_id      TEXT PRIMARY KEY,
  vendor          TEXT NOT NULL,
  kind            TEXT NOT NULL,
  subject_type    TEXT NOT NULL,
  subject_value   TEXT NOT NULL,
  watchlist_entry TEXT,
  counts_json     TEXT,
  data_classes    TEXT,
  first_seen      TEXT,
  observed_at     TEXT NOT NULL,
  source_ref      TEXT,
  confidence      TEXT NOT NULL,
  licence_scope   TEXT NOT NULL,
  stix_exportable INTEGER NOT NULL DEFAULT 0,
  has_pi          INTEGER NOT NULL DEFAULT 0,
  expires_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS exposures_subject ON exposures(subject_type, subject_value);
"""

_RETENTION_DAYS = 90


def _iso(moment: datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class ExposureStore:
    def __init__(self, path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def write(
        self,
        finding: ExposureFinding,
        *,
        terms: TermsProfile,
        watchlist: Watchlist,
        values: dict | None = None,
        now: datetime | None = None,
    ) -> str:
        finding = clamp_to_terms(canonical_finding(finding), terms)
        if finding.subject.value.casefold() not in watchlist.known_subjects():
            return "dropped_third_party"
        if terms.store == "none":
            return "dropped_store_none"
        kept_values = values if terms.store == "full" else None
        if kept_values is not None:
            # Full store still never keeps plaintext secrets. There is no values column.
            redact_obj(kept_values)
        row = _row(finding, now=now or finding.observed_at)
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT 1 FROM exposures WHERE finding_id = ?",
                (row["finding_id"],),
            ).fetchone()
            if existing:
                conn.execute(
                    """
                    UPDATE exposures
                    SET observed_at = ?, counts_json = ?
                    WHERE finding_id = ?
                    """,
                    (row["observed_at"], row["counts_json"], row["finding_id"]),
                )
                return "updated"
            columns = list(row)
            placeholders = ", ".join("?" for _ in columns)
            conn.execute(
                f"INSERT INTO exposures ({', '.join(columns)}) VALUES ({placeholders})",
                tuple(row[column] for column in columns),
            )
        return "stored"

    def get(self, finding_id: str) -> sqlite3.Row | None:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM exposures WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()

    def rows(self) -> list[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute("SELECT * FROM exposures ORDER BY finding_id").fetchall()

    def delete_expired(self, now: datetime) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM exposures WHERE expires_at < ?",
                (_iso(now),),
            )
            return cursor.rowcount

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn


def _row(finding: ExposureFinding, *, now: datetime) -> dict:
    observed = finding.observed_at
    first = finding.first_seen or observed
    data_classes = None
    if finding.data_classes is not None:
        data_classes = json.dumps([redact_text(item) for item in finding.data_classes])
    counts = None if finding.counts is None else json.dumps(finding.counts)
    source_ref = None if finding.source_ref is None else redact_text(finding.source_ref)
    watchlist_entry = finding.subject.watchlist_entry
    if watchlist_entry is not None:
        watchlist_entry = redact_text(watchlist_entry)
    return {
        "finding_id": finding.finding_id,
        "vendor": finding.vendor,
        "kind": finding.kind,
        "subject_type": finding.subject.type,
        "subject_value": redact_text(finding.subject.value),
        "watchlist_entry": watchlist_entry,
        "counts_json": counts,
        "data_classes": data_classes,
        "first_seen": _iso(first),
        "observed_at": _iso(observed),
        "source_ref": source_ref,
        "confidence": finding.confidence,
        "licence_scope": finding.licence_scope,
        "stix_exportable": 1 if finding.stix_exportable else 0,
        "has_pi": 1 if finding.contains_personal_information else 0,
        "expires_at": _iso(now + timedelta(days=_RETENTION_DAYS)),
    }
