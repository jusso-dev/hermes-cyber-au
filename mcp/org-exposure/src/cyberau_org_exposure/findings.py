"""Normalise, store and present exposure findings for the user's watchlist."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from cyberau_common.secrets import redact

from cyberau_org_exposure.abn import data_dir
from cyberau_org_exposure.watchlist import CONFIDENCE, OrgProfile

KINDS = (
    "infostealer_credential",
    "breach_credential",
    "leak_site_claim",
    "data_leak_disclosure",
    "dark_web_mention",
    "typosquat_domain",
    "brand_impersonation",
    "attack_surface_issue",
)
LICENCE_SCOPES = ("session_only", "store_metadata", "store_full")
SUBJECT_TYPES = ("domain", "abn", "brand", "email_domain", "ip")
CONFIDENCE_RANK = {
    "unverified_claim": 0,
    "vendor_reported": 1,
    "vendor_confirmed": 2,
}
_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
_SECRET = re.compile(r"(?i)\b(password|passwd|secret|cookie|token|api[_-]?key)\b\s*[:=]\s*\S+")
_ACTOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}$")

NDB_NOTE = (
    "A finding about your own organisation includes personal information. "
    "That can start the clock for assessing a suspected eligible data breach "
    "under the Notifiable Data Breaches scheme. This is not legal advice. "
    "The ndb-breach-notification skill can draft an assessment. "
    "Do not contact the OAIC, ASD, affected people or any vendor. A person decides."
)

STORE_SQL = """
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


def prepare_finding(raw: dict, vendor: str, profile: OrgProfile) -> tuple[dict, str] | None:
    """Return a schema-shaped finding and a display actor, or None when it is out of scope."""
    if not isinstance(raw, dict):
        return None
    subject = raw.get("subject")
    if not isinstance(subject, dict):
        return None
    subject_type = subject.get("type")
    value = subject.get("value")
    if subject_type not in SUBJECT_TYPES or not isinstance(value, str):
        return None
    value = _redact_text(value)
    if not profile.matches(subject_type, value):
        return None
    kind = raw.get("kind")
    confidence = raw.get("confidence")
    observed_at = raw.get("observed_at")
    if kind not in KINDS or confidence not in CONFIDENCE or not isinstance(observed_at, str):
        return None
    if not _DATETIME.fullmatch(observed_at):
        return None
    canonical = profile.canonical(subject_type, value)
    source_ref = raw.get("source_ref")
    if source_ref is None:
        source_ref = ""
    if not isinstance(source_ref, str):
        return None
    source_ref = _redact_text(source_ref)
    licence = raw.get("licence_scope", "store_metadata")
    if licence not in LICENCE_SCOPES:
        return None
    first_seen = raw.get("first_seen")
    if first_seen is not None and (
        not isinstance(first_seen, str) or not _DATETIME.fullmatch(first_seen)
    ):
        return None
    finding = {
        "finding_id": _finding_id(vendor, kind, canonical, source_ref),
        "vendor": vendor,
        "kind": kind,
        "subject": {
            "type": subject_type,
            "value": canonical,
            "watchlist_entry": profile.entry_id(subject_type, canonical),
        },
        "observed_at": observed_at,
        "licence_scope": licence,
        "confidence": confidence,
        "stix_exportable": bool(raw.get("stix_exportable", False)),
        "contains_personal_information": bool(raw.get("contains_personal_information", False)),
    }
    if first_seen:
        finding["first_seen"] = first_seen
    if source_ref:
        finding["source_ref"] = source_ref
    counts = raw.get("counts")
    if isinstance(counts, dict) and all(_plain_int(item) for item in counts.values()):
        finding["counts"] = counts
    classes = raw.get("data_classes")
    if isinstance(classes, list) and all(isinstance(item, str) for item in classes):
        finding["data_classes"] = [_redact_text(item) for item in classes]
    return finding, _actor(raw.get("actor") or raw.get("claimed_by"))


def meets_confidence(confidence: str, minimum: str) -> bool:
    return CONFIDENCE_RANK[confidence] >= CONFIDENCE_RANK[minimum]


def on_or_after(observed_at: str, since: str | None) -> bool:
    if not since:
        return True
    return observed_at[:10] >= since


def group_findings(findings: list[dict], actors: dict[str, str]) -> list[dict]:
    """Group by subject and kind, newest observed_at first."""
    buckets: dict[tuple[str, str, str], list[dict]] = {}
    for finding in findings:
        subject = finding["subject"]
        key = (subject["type"], subject["value"], finding["kind"])
        buckets.setdefault(key, []).append(finding)
    groups = []
    for (_subject_type, _value, kind), rows in buckets.items():
        rows.sort(key=lambda item: item["observed_at"], reverse=True)
        groups.append(
            {
                "subject": rows[0]["subject"],
                "kind": kind,
                "findings": [_public_row(row, actors.get(row["finding_id"], "")) for row in rows],
            }
        )
    groups.sort(key=lambda group: group["findings"][0]["observed_at"], reverse=True)
    return groups


def store_findings(findings: list[dict], path: Path | None = None) -> None:
    """Persist findings the licence allows. session_only rows stay out of the store."""
    rows = [finding for finding in findings if finding["licence_scope"] != "session_only"]
    if not rows:
        return
    target = path or (data_dir() / "exposures.sqlite")
    with _connect(target) as conn:
        for finding in rows:
            counts = finding.get("counts")
            classes = finding.get("data_classes")
            conn.execute(
                """
                INSERT INTO exposures (
                  finding_id, vendor, kind, subject_type, subject_value, watchlist_entry,
                  counts_json, data_classes, first_seen, observed_at, source_ref,
                  confidence, licence_scope, stix_exportable, has_pi, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                  observed_at = excluded.observed_at,
                  counts_json = excluded.counts_json
                """,
                (
                    finding["finding_id"],
                    finding["vendor"],
                    finding["kind"],
                    finding["subject"]["type"],
                    finding["subject"]["value"],
                    finding["subject"].get("watchlist_entry"),
                    json.dumps(counts, sort_keys=True) if counts is not None else None,
                    json.dumps(classes) if classes is not None else None,
                    finding.get("first_seen"),
                    finding["observed_at"],
                    finding.get("source_ref"),
                    finding["confidence"],
                    finding["licence_scope"],
                    1 if finding.get("stix_exportable") else 0,
                    1 if finding.get("contains_personal_information") else 0,
                    _expires(finding["observed_at"]),
                ),
            )


def stored_values(path: Path | None = None) -> list[str]:
    target = path or (data_dir() / "exposures.sqlite")
    if not target.is_file():
        return []
    with _connect(target) as conn:
        rows = conn.execute("SELECT subject_value FROM exposures").fetchall()
    return [row["subject_value"] for row in rows]


def _public_row(finding: dict, actor: str) -> dict:
    day = (finding.get("first_seen") or finding["observed_at"])[:10]
    if finding["kind"] == "leak_site_claim":
        who = actor or "an unnamed group"
        line = f"claimed by {who} on {day}, not confirmed"
    else:
        line = f"{finding['vendor']}, {finding['confidence']}, first seen {day}"
    row = {
        "finding_id": finding["finding_id"],
        "vendor": finding["vendor"],
        "confidence": finding["confidence"],
        "first_seen": finding.get("first_seen") or finding["observed_at"],
        "observed_at": finding["observed_at"],
        "line": line,
    }
    return row


def _plain_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _actor(value) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = _redact_text(value)
    if _ACTOR.fullmatch(cleaned):
        return cleaned
    return ""


def _redact_text(value: str) -> str:
    return _SECRET.sub("[redacted]", redact(value))


def _finding_id(vendor: str, kind: str, subject_value: str, source_ref: str) -> str:
    material = f"{vendor}|{kind}|{subject_value}|{source_ref}"
    return hashlib.sha256(material.encode()).hexdigest()


def _expires(observed_at: str) -> str:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    return (parsed + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(STORE_SQL)
    return conn
