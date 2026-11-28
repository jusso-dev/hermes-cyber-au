"""Exposure findings for the daily briefing, incident triage, NDB and the executive page.

Reads the ``exposures`` table that premium connectors and the exposure watch write in
the profile data directory. Nothing here calls a vendor or sends anything. Rows are
metadata only (the store never keeps credential values), and each one carries
``share_outside_profile`` from its vendor's terms so a renderer can hold it back from a
channel that is not the owner's.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml
from cyberau_common import runtime
from cyberau_common.envelope import envelope

from cyberau_org_exposure.abn import data_dir

SYDNEY = ZoneInfo("Australia/Sydney")
STORE_FILES = ("exposures.sqlite", "intel.sqlite")
STATE_FILE = "exposure-brief-state.json"
DEFAULT_LOOKBACK_DAYS = 7
TREND_DAYS = 7
ATTRIBUTION = (
    "Exposure findings are untrusted vendor data, metadata only. "
    "Leak site claims are allegations, not confirmations. Not legal advice."
)
_COLUMNS = (
    "finding_id",
    "vendor",
    "kind",
    "subject_type",
    "subject_value",
    "counts_json",
    "data_classes",
    "first_seen",
    "observed_at",
    "confidence",
    "licence_scope",
    "stix_exportable",
    "has_pi",
)


def store_rows(directory: Path | None = None) -> list[dict]:
    """Every exposure row in the profile data directory, one per finding id."""
    base = directory or data_dir()
    found: dict[str, dict] = {}
    for name in STORE_FILES:
        path = base / name
        if not path.is_file():
            continue
        for row in _read(path):
            current = found.get(row["finding_id"])
            if current is None or row["observed_at"] > current["observed_at"]:
                found[row["finding_id"]] = row
    return sorted(found.values(), key=lambda row: (row["observed_at"], row["finding_id"]))


def profile_config(path: Path | None = None) -> dict:
    """The profile config.yaml, or an empty mapping. Only premium settings are used."""
    target = path or _config_path()
    if not target.is_file():
        return {}
    try:
        data = yaml.safe_load(target.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    return data if isinstance(data, dict) else {}


def premium_state(config: dict) -> tuple[list[str], dict[str, bool]]:
    """Enabled paid vendors, and share_outside_profile for every catalogue vendor."""
    from cyberau_premium.catalog import TermsRejected, apply_terms, load_vendors, vendor_config

    enabled: list[str] = []
    share: dict[str, bool] = {}
    for spec in load_vendors():
        try:
            terms = apply_terms(spec, config)
        except TermsRejected:
            terms = spec.terms
        share[spec.server] = bool(terms.share_outside_profile)
        if spec.paid and _enabled(config, spec.server, vendor_config(config, spec.server)):
            enabled.append(spec.server)
    return sorted(enabled), share


def brief_payload(
    *,
    now: datetime | None = None,
    since: datetime | None = None,
    config: dict | None = None,
    directory: Path | None = None,
    record: bool = False,
) -> dict:
    """Envelope for the daily briefing ``org-exposure`` connector entry.

    New means a finding id not already briefed and observed at or after ``since``
    (default: the last recorded briefing, else seven days back). ``record`` remembers
    the ids so the next briefing does not repeat them.
    """
    moment = _sydney(now)
    base = directory or data_dir()
    settings = profile_config() if config is None else config
    premium, share = premium_state(settings)
    state = _load_state(base)
    start = since or _parse(state.get("last")) or moment - timedelta(days=DEFAULT_LOOKBACK_DAYS)
    briefed = set(state.get("briefed") or [])
    rows = store_rows(base)
    findings = []
    for row in rows:
        if row["finding_id"] in briefed:
            continue
        observed = _parse(row["observed_at"])
        if observed is None or not start <= observed <= moment:
            continue
        findings.append(_public(row, share))
    data = {
        "premium_enabled": premium,
        "since": start.isoformat(timespec="seconds"),
        "findings": findings,
        "trend": trend(rows, now=moment),
    }
    if record:
        present = {row["finding_id"] for row in rows}
        kept = (briefed & present) | {item["finding_id"] for item in findings}
        _save_state(base, {"last": moment.isoformat(timespec="seconds"), "briefed": sorted(kept)})
    return envelope("org-exposure", data, cache="snapshot", attribution=ATTRIBUTION)


def trend(rows: list[dict], *, now: datetime, days: int = TREND_DAYS) -> dict:
    """Counts only: findings observed in the last ``days`` against the ``days`` before."""
    end = _sydney(now)
    middle = end - timedelta(days=days)
    start = middle - timedelta(days=days)
    current: dict[str, int] = {}
    previous = 0
    for row in rows:
        observed = _parse(row["observed_at"])
        if observed is None:
            continue
        if middle <= observed < end:
            current[row["kind"]] = current.get(row["kind"], 0) + 1
        elif start <= observed < middle:
            previous += 1
    total = sum(current.values())
    if total > previous:
        direction = f"up from {previous}"
    elif total < previous:
        direction = f"down from {previous}"
    else:
        direction = "the same as"
    noun = "finding" if total == 1 else "findings"
    line = f"Exposure of our organisation: {total} new {noun} in the last {days} days, "
    if direction == "the same as":
        line += f"the same as the {days} days before"
    else:
        line += f"{direction} in the {days} days before"
    if current:
        line += " (" + ", ".join(f"{current[kind]} {kind}" for kind in sorted(current)) + ")"
    line += ". Counts only."
    return {
        "days": days,
        "current": total,
        "previous": previous,
        "by_kind": dict(sorted(current.items())),
        "line": line,
    }


def finding_payload(
    finding_id: str, *, config: dict | None = None, directory: Path | None = None
) -> dict:
    """One finding by id, for the NDB prefill. Metadata only, never a credential value."""
    settings = profile_config() if config is None else config
    _premium, share = premium_state(settings)
    for row in store_rows(directory):
        if row["finding_id"] == finding_id:
            data = {"found": True, "finding": _public(row, share, detail=True)}
            return envelope("org-exposure", data, cache="snapshot", attribution=ATTRIBUTION)
    data = {"found": False, "finding_id": finding_id}
    return envelope(
        "org-exposure",
        data,
        cache="snapshot",
        attribution=ATTRIBUTION,
        warnings=["no exposure finding with that id in the profile store"],
    )


def _public(row: dict, share: dict[str, bool], *, detail: bool = False) -> dict:
    confidence = row["confidence"]
    if row["kind"] == "leak_site_claim":
        confidence = "unverified_claim"
    item = {
        "finding_id": row["finding_id"],
        "vendor": row["vendor"],
        "kind": row["kind"],
        "subject": {"type": row["subject_type"], "value": row["subject_value"]},
        "confidence": confidence,
        "first_seen": row["first_seen"] or row["observed_at"],
        "observed_at": row["observed_at"],
        "counts": row["counts"],
        "share_outside_profile": share.get(row["vendor"], False),
        "stix_exportable": row["stix_exportable"],
    }
    if detail:
        item["data_classes"] = row["data_classes"]
        item["contains_personal_information"] = row["has_pi"]
    return item


def _read(path: Path) -> list[dict]:
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error:
        return []
    conn.row_factory = sqlite3.Row
    try:
        found = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'exposures'"
        ).fetchone()
        if found is None:
            return []
        rows = conn.execute(f"SELECT {', '.join(_COLUMNS)} FROM exposures").fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()
    return [_row(dict(row)) for row in rows]


def _row(raw: dict) -> dict:
    counts = _json(raw.get("counts_json"), dict)
    classes = _json(raw.get("data_classes"), list)
    return {
        "finding_id": str(raw["finding_id"]),
        "vendor": str(raw["vendor"]),
        "kind": str(raw["kind"]),
        "subject_type": str(raw["subject_type"]),
        "subject_value": str(raw["subject_value"]),
        "counts": {
            str(key): value
            for key, value in sorted((counts or {}).items())
            if isinstance(value, int) and not isinstance(value, bool)
        },
        "data_classes": [str(item) for item in classes or [] if isinstance(item, str)],
        "first_seen": raw.get("first_seen"),
        "observed_at": str(raw["observed_at"]),
        "confidence": str(raw["confidence"]),
        "licence_scope": str(raw["licence_scope"]),
        "stix_exportable": bool(raw.get("stix_exportable")),
        "has_pi": bool(raw.get("has_pi")),
    }


def _json(text, kind):
    if not text:
        return None
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, kind) else None


def _enabled(config: dict, server: str, block: dict) -> bool:
    servers = config.get("mcp_servers") or {}
    entry = servers.get(server) if isinstance(servers, dict) else None
    if isinstance(entry, dict) and "enabled" in entry:
        return entry["enabled"] is True
    return block.get("enabled") is True


def _config_path() -> Path:
    if os.environ.get("HERMES_HOME", "").strip():
        return runtime.profile_home() / "config.yaml"
    configured = runtime.configured_data_dir()
    if configured is not None:
        return configured.absolute().parent.parent / "config.yaml"
    return runtime.profile_home() / "config.yaml"


def _load_state(base: Path) -> dict:
    path = base / STATE_FILE
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_state(base: Path, state: dict) -> None:
    base.mkdir(parents=True, exist_ok=True)
    path = base / STATE_FILE
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _parse(value) -> datetime | None:
    if not isinstance(value, str) or "T" not in value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(SYDNEY)


def _sydney(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(SYDNEY)
    if now.tzinfo is None:
        raise ValueError("now needs a timezone")
    return now.astimezone(SYDNEY)
