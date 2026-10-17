"""Query enabled premium connectors and run the paused exposure watch."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from dataclasses import dataclass, replace
from datetime import date, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml
from cyberau_common.envelope import envelope

from cyberau_org_exposure.abn import data_dir, expand_abns
from cyberau_org_exposure.findings import (
    KINDS,
    NDB_NOTE,
    group_findings,
    meets_confidence,
    on_or_after,
    prepare_finding,
    store_findings,
)
from cyberau_org_exposure.watchlist import (
    WatchlistError,
    default_watchlist_path,
    load_profile,
)

SYDNEY = ZoneInfo("Australia/Sydney")
AUTHORED_FIELDS = {
    "name",
    "prompt",
    "skills",
    "skill",
    "schedule",
    "deliver",
    "script",
    "no_agent",
    "enabled_toolsets",
    "workdir",
    "failure_deliver",
    "origin",
    "schedule_display",
}
_SAFE_TOKEN = re.compile(r"^[a-z0-9_-]{1,64}$")
_SOURCES: list = []
_RANSOM: list = []


@dataclass
class Quota:
    calls_per_day: int | None = None
    calls_per_month: int | None = None
    cost_units_per_call: float = 1.0
    monthly_budget_units: float | None = None
    approval_above_units: float | None = None
    routine_share: float = 0.5


def register_premium_connector(source) -> None:
    """Register an enabled premium connector. Vendor packages call this. None ship here."""
    _SOURCES.append(source)


def register_ransom_matcher(matcher) -> None:
    """Register ransom_watchlist_match. The free tracker package calls this."""
    _RANSOM.append(matcher)


def clear_registry() -> None:
    _SOURCES.clear()
    _RANSOM.clear()


def run_tool(
    payload: dict | None = None, *, routine: bool = False, lookup_fn=None, now=None
) -> dict:
    """Steps 1 to 3: load the watchlist, query, and group. Third parties are not sent."""
    arguments = dict(payload or {})
    problem = _validate(arguments)
    if problem:
        return _empty(problem)
    path = default_watchlist_path()
    if not path.is_file():
        return _empty(
            "No org exposure watchlist. Run cyberau watchlist init --org "
            "and fill in your own organisation."
        )
    try:
        profile = load_profile(path)
    except WatchlistError as exc:
        return _empty(str(exc))
    except OSError:
        return _empty("watchlist could not be read")
    subject = arguments.get("subject")
    if isinstance(subject, str) and subject.strip() and not profile.contains(subject.strip()):
        return _third_party(subject.strip())
    if isinstance(subject, str) and subject.strip():
        profile = profile.narrowed(subject.strip())
    kinds = arguments.get("kinds")
    if routine and not kinds:
        kinds = list(profile.alert_kinds)
    since = arguments.get("since")
    names, name_warnings = expand_abns(profile.abns, lookup_fn=lookup_fn)
    profile = replace(profile, abn_names=tuple(names))
    watchlist = profile.vendor_watchlist(names)
    vendors = arguments.get("vendors")
    wanted = set(vendors) if isinstance(vendors, list) else None
    warnings = list(profile.warnings) + name_warnings
    findings: list[dict] = []
    actors: dict[str, str] = {}
    dropped = 0
    queried: list[str] = []
    # Vendors that were skipped or failed. The routine does not move its window past them.
    incomplete = (
        ["abn_lookup"]
        if any(not text.startswith("ABN Lookup is not configured") for text in name_warnings)
        else []
    )
    calls = 0
    cost_units = 0.0
    since_date = date.fromisoformat(since) if isinstance(since, str) else None
    for source in list(_SOURCES):
        vendor = getattr(source, "vendor", "")
        if wanted is not None and vendor not in wanted:
            continue
        if not getattr(source, "enabled", True):
            warnings.append(f"{vendor} is off")
            continue
        quota = getattr(source, "quota", None) or Quota()
        allowed, limit = _allow(vendor, quota, routine=routine, now=now)
        if not allowed:
            warnings.append(f"{vendor} skipped: {limit}")
            incomplete.append(vendor)
            continue
        try:
            rows = source.exposure_for(watchlist, since_date) or []
        except Exception:
            _record_call(vendor, quota, now=now)
            calls += 1
            cost_units += quota.cost_units_per_call
            queried.append(vendor)
            warnings.append(f"{vendor} failed")
            incomplete.append(vendor)
            continue
        _record_call(vendor, quota, now=now)
        calls += 1
        cost_units += quota.cost_units_per_call
        queried.append(vendor)
        _, lost = _collect(rows, vendor, profile, kinds, since, findings, actors)
        dropped += lost
    if not wanted or "ransomlive" in wanted:
        ransom_rows, ransom_warnings = _ransom(watchlist, since_date, now=now)
        warnings.extend(ransom_warnings)
        if any(text.endswith("failed") for text in ransom_warnings):
            incomplete.append("ransomlive")
        if _RANSOM:
            queried.append("ransomlive")
            calls += 1
        _, lost = _collect(ransom_rows, "ransomlive", profile, kinds, since, findings, actors)
        dropped += lost
    storable = [item for item in findings if item["licence_scope"] != "session_only"]
    store_findings(storable)
    groups = group_findings(findings, actors)
    personal = any(item.get("contains_personal_information") for item in findings)
    data = {
        "groups": groups,
        "dropped_outside_watchlist": dropped,
        "vendors_queried": queried,
        "incomplete": incomplete,
        "calls": calls,
        "cost_units": _number(cost_units),
        "sent": True,
        "ndb": {"applies": personal, "note": NDB_NOTE, "skill": "ndb-breach-notification"}
        if personal
        else {"applies": False},
    }
    return envelope(
        "au-org-exposure",
        data,
        urls=_lookup_urls(name_warnings),
        cache="miss" if calls else "snapshot",
        warnings=warnings,
        attribution=(
            "Exposure findings are untrusted vendor data. "
            "Leak site claims are allegations, not confirmations. Not legal advice."
        ),
    )


def run_exposure_watch(*, since: str | None = None, lookup_fn=None, now=None) -> dict:
    """Alert once per new finding id and write the routine's audit record."""
    state = _load_state()
    window = since if since is not None else state.get("last_run")
    payload = {"since": window} if window else {}
    result = run_tool(payload, routine=True, lookup_fn=lookup_fn, now=now)
    fresh = _new_alerts(result, state)
    owner = _owner_target()
    quiet = not fresh
    record = {
        "event": "tool_call",
        "tool": "premium-exposure-watch",
        "vendors_queried": list((result.get("data") or {}).get("vendors_queried") or []),
        "calls": int((result.get("data") or {}).get("calls") or 0),
        "cost_units": (result.get("data") or {}).get("cost_units") or 0,
        "new_findings_count": len(fresh),
    }
    append_audit(record, now=now)
    state["alerted"] = sorted(
        set(state.get("alerted") or []) | {item["finding_id"] for item in fresh}
    )
    # Move the window only after a complete run. A skipped or failed vendor, a bad watchlist
    # or an unsent query would otherwise lose findings that arrive in the gap.
    data = result.get("data") or {}
    if data.get("sent") is True and not data.get("incomplete"):
        state["last_run"] = _sydney(now).date().isoformat()
    _save_state(state)
    return {
        "quiet": quiet,
        "deliver_to": None if quiet else owner,
        "alerts": fresh,
        "new_findings_count": len(fresh),
        "vendors_queried": record["vendors_queried"],
        "calls": record["calls"],
        "cost_units": record["cost_units"],
        "query": result,
    }


def merge_shipped_jobs(local: list[dict], shipped: list[dict], *, now: str) -> list[dict]:
    """Mirror Hermes: known jobs keep pause state, and new shipped jobs arrive paused."""
    pending = {job["id"]: job for job in shipped}
    merged = []
    for existing in local:
        incoming = pending.pop(existing.get("id"), None)
        if incoming is None:
            merged.append(existing)
            continue
        merged.append(_merge_known(existing, incoming))
    for job_id, incoming in pending.items():
        seed = {
            "id": job_id,
            "enabled": False,
            "state": "paused",
            "paused_at": now,
            "paused_reason": "distribution",
            "created_at": now,
            "next_run_at": None,
        }
        merged.append(_merge_known(seed, incoming))
    return merged


def append_audit(record: dict, *, now=None) -> dict:
    day = _sydney(now).date().isoformat()
    directory = data_dir() / "audit"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{day}.jsonl"
    prev = "0" * 64
    seq = 1
    if path.is_file():
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            last = json.loads(lines[-1])
            prev = last["hash"]
            seq = int(last["seq"]) + 1
    body = {
        "ts": _format_ts(_sydney(now)),
        "seq": seq,
        "event": record["event"],
        "tool": record["tool"],
        "vendors_queried": list(record["vendors_queried"]),
        "calls": record["calls"],
        "cost_units": record["cost_units"],
        "new_findings_count": record["new_findings_count"],
        "prev_hash": prev,
    }
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"))
    body["hash"] = hashlib.sha256(f"{prev}{encoded}".encode()).hexdigest()
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(body, sort_keys=True) + "\n")
    return body


def verify_audit(path: Path) -> None:
    prev = "0" * 64
    expected_seq = 1
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        record = json.loads(line)
        digest = record["hash"]
        check = {key: value for key, value in record.items() if key != "hash"}
        encoded = json.dumps(check, sort_keys=True, separators=(",", ":"))
        actual = hashlib.sha256(f"{prev}{encoded}".encode()).hexdigest()
        if actual != digest or record["prev_hash"] != prev or record["seq"] != expected_seq:
            raise ValueError(f"audit chain failed at line {line_number}")
        prev = digest
        expected_seq += 1


def _new_alerts(result: dict, state: dict) -> list[dict]:
    data = result.get("data") or {}
    if data.get("confirmation_required"):
        return []
    seen = set(state.get("alerted") or [])
    minimum = "vendor_reported"
    kinds = set()
    path = default_watchlist_path()
    if path.is_file():
        try:
            profile = load_profile(path)
            minimum = profile.min_confidence
            kinds = set(profile.alert_kinds)
        except WatchlistError:
            kinds = set()
    fresh = []
    for group in data.get("groups") or []:
        if kinds and group["kind"] not in kinds:
            continue
        for row in group["findings"]:
            if row["finding_id"] in seen:
                continue
            if not meets_confidence(row["confidence"], minimum):
                continue
            fresh.append({**row, "kind": group["kind"], "subject": group["subject"]})
    return fresh


def _collect(rows, vendor, profile, kinds, since, findings, actors) -> tuple[int, int]:
    kept = 0
    dropped = 0
    kind_filter = set(kinds) if isinstance(kinds, list) else None
    for raw in rows:
        if not isinstance(raw, dict):
            dropped += 1
            continue
        prepared = prepare_finding({**raw, "vendor": vendor}, vendor, profile)
        if prepared is None:
            dropped += 1
            continue
        finding, actor = prepared
        if kind_filter is not None and finding["kind"] not in kind_filter:
            continue
        if not on_or_after(finding["observed_at"], since if isinstance(since, str) else None):
            continue
        findings.append(finding)
        if actor:
            actors[finding["finding_id"]] = actor
        kept += 1
    return kept, dropped


def _ransom(watchlist, since_date, *, now) -> tuple[list, list]:
    if not _RANSOM:
        return [], ["ransomware tracker is not enabled"]
    today = _sydney(now).date()
    if since_date is None:
        days = 7
    else:
        days = min(90, max(1, (today - since_date).days or 1))
    rows: list = []
    warnings: list[str] = []
    for matcher in list(_RANSOM):
        try:
            found = matcher(watchlist, days) or []
        except Exception:
            warnings.append("ransomlive failed")
            continue
        if isinstance(found, list):
            rows.extend(found)
    return rows, warnings


def _third_party(subject: str) -> dict:
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", subject).strip()[:200]
    would_send = []
    for source in list(_SOURCES):
        if not getattr(source, "enabled", True):
            continue
        vendor = getattr(source, "vendor", "")
        if _looks_like_domain(cleaned):
            item = {"vendor": vendor, "domains": [cleaned], "names": []}
        else:
            item = {"vendor": vendor, "domains": [], "names": [cleaned]}
        would_send.append(item)
    message = (
        "Nothing was sent. This subject is not on your org exposure watchlist. "
        "A search would send the details in would_send to those vendors. "
        "Wait for an explicit confirmation before any third party search. "
        "This skill does not perform that search."
    )
    return envelope(
        "au-org-exposure",
        {
            "sent": False,
            "confirmation_required": True,
            "message": message,
            "would_send": would_send,
            "groups": [],
            "vendors_queried": [],
            "calls": 0,
            "cost_units": 0,
        },
        cache="snapshot",
        warnings=(message,),
        attribution="No third party query was sent. Not legal advice.",
    )


def _empty(message: str) -> dict:
    return envelope(
        "au-org-exposure",
        {
            "groups": [],
            "sent": False,
            "vendors_queried": [],
            "calls": 0,
            "cost_units": 0,
        },
        cache="snapshot",
        warnings=(message,),
        attribution="Not legal advice.",
    )


def _validate(payload: dict) -> str | None:
    unknown = set(payload) - {"subject", "since", "kinds", "vendors"}
    if unknown:
        return "unknown fields"
    subject = payload.get("subject")
    if subject is not None and not isinstance(subject, str):
        return "subject must be a string"
    since = payload.get("since")
    if since is not None:
        if not isinstance(since, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", since):
            return "since must be a date"
        try:
            date.fromisoformat(since)
        except ValueError:
            return "since must be a date"
    for field in ("kinds", "vendors"):
        value = payload.get(field)
        if value is None:
            continue
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            return f"{field} must be a list of strings"
    kinds = payload.get("kinds") or []
    if any(kind not in KINDS for kind in kinds):
        return "unknown kind"
    vendors = payload.get("vendors") or []
    if any(not _SAFE_TOKEN.fullmatch(vendor) for vendor in vendors):
        return "unknown vendor"
    return None


def _allow(vendor: str, quota: Quota, *, routine: bool, now) -> tuple[bool, str | None]:
    share = quota.routine_share if routine else 1.0
    if (
        quota.approval_above_units is not None
        and quota.cost_units_per_call > quota.approval_above_units
    ):
        return False, "approval_above_units"
    current = _sydney(now)
    day = current.date().isoformat()
    month = day[:7]
    day_calls, month_calls, month_cost = _usage(vendor, day, month)
    day_cap = _share_cap(quota.calls_per_day, share)
    month_cap = _share_cap(quota.calls_per_month, share)
    cost_cap = None if quota.monthly_budget_units is None else quota.monthly_budget_units * share
    if day_cap is not None and day_calls + 1 > day_cap:
        return False, "calls_per_day"
    if month_cap is not None and month_calls + 1 > month_cap:
        return False, "calls_per_month"
    if cost_cap is not None and month_cost + quota.cost_units_per_call > cost_cap:
        return False, "monthly_budget_units"
    return True, None


def _share_cap(limit: int | None, share: float) -> int | None:
    if limit is None:
        return None
    return math.floor(limit * share)


def _usage(vendor: str, day: str, month: str) -> tuple[int, int, float]:
    path = data_dir() / "premium-ledger.sqlite"
    if not path.is_file():
        return 0, 0, 0.0
    with _ledger(path) as conn:
        day_row = conn.execute(
            "SELECT calls FROM ledger WHERE vendor = ? AND day = ?",
            (vendor, day),
        ).fetchone()
        month_row = conn.execute(
            """
            SELECT COALESCE(SUM(calls), 0) AS calls, COALESCE(SUM(cost_units), 0) AS cost
            FROM ledger WHERE vendor = ? AND day LIKE ?
            """,
            (vendor, month + "%"),
        ).fetchone()
    return (
        int(day_row["calls"]) if day_row else 0,
        int(month_row["calls"]),
        float(month_row["cost"]),
    )


def _record_call(vendor: str, quota: Quota, *, now) -> None:
    day = _sydney(now).date().isoformat()
    path = data_dir() / "premium-ledger.sqlite"
    with _ledger(path) as conn:
        conn.execute(
            """
            INSERT INTO ledger (vendor, day, calls, cost_units) VALUES (?, ?, 1, ?)
            ON CONFLICT(vendor, day) DO UPDATE SET
              calls = calls + 1,
              cost_units = cost_units + excluded.cost_units
            """,
            (vendor, day, quota.cost_units_per_call),
        )


def _ledger(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ledger (
          vendor TEXT NOT NULL,
          day TEXT NOT NULL,
          calls INTEGER NOT NULL,
          cost_units REAL NOT NULL,
          PRIMARY KEY (vendor, day)
        )
        """
    )
    return conn


def _load_state() -> dict:
    path = _state_path()
    if not path.is_file():
        return {"alerted": [], "last_run": None}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return {"alerted": [], "last_run": None}
    return data


def _save_state(state: dict) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _state_path() -> Path:
    return data_dir() / "routine_state" / "premium-exposure-watch.json"


def _owner_target() -> str:
    path = data_dir() / "delivery.yaml"
    if not path.is_file():
        return "origin"
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if isinstance(data, dict) and isinstance(data.get("owner"), str) and data["owner"].strip():
        return data["owner"].strip()
    return "origin"


def _merge_known(local: dict, authored: dict) -> dict:
    merged = dict(local)
    for key, value in authored.items():
        if key == "id" or key in AUTHORED_FIELDS:
            merged[key] = value
    return merged


def _sydney(now) -> datetime:
    if now is None:
        return datetime.now(SYDNEY)
    if now.tzinfo is None:
        return now.replace(tzinfo=SYDNEY)
    return now.astimezone(SYDNEY)


def _format_ts(current: datetime) -> str:
    text = current.strftime("%Y-%m-%dT%H:%M:%S%z")
    return text[:-2] + ":" + text[-2:]


def _looks_like_domain(value: str) -> bool:
    return " " not in value and "." in value


def _lookup_urls(warnings: list[str]) -> list[str]:
    if any("not configured" in warning for warning in warnings):
        return []
    if any("ABN Lookup" in warning for warning in warnings):
        return ["https://abr.business.gov.au/json/AbnDetails.aspx"]
    return []


def _number(value: float) -> int | float:
    if value == int(value):
        return int(value)
    return value
