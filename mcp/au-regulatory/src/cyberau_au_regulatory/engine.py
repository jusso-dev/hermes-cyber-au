"""Which Australian incident reports may apply, and by when. Pure and deterministic.

``check`` takes the reviewed obligations snapshot, an organisation profile (the
``org.yaml`` mapping), incident facts and a discovery time. It returns the rules that
apply, the rules that might apply once a question is answered, the rules that do not
apply and why, deadlines in Australia/Sydney, recipients, sources, draft report fields
and a countdown timeline.

No network, no clock (pass ``now`` for a countdown), no file writes. Nothing is
submitted to anyone. This is guidance, not legal advice.

Applicability conditions live in the snapshot under ``applies_when``. A condition is
``{"all": [...]}``, ``{"any": [...]}`` or a leaf that reads one ``org`` field or one
incident ``fact``:

- ``equals`` (a value), ``in`` (a list), ``not_in`` (a list) or ``contains`` (for a list
  field such as ``regulators``)
- ``unknown_values``: org values that make the answer unknown, so the engine asks
- ``missing``: for a fact, what an absent value means: ``"unknown"`` (the default),
  ``"false"`` or ``"true"``
- ``org_false_means_no``: for a fact, an org boolean that answers "no" when the fact is
  absent and the org field is false (``holds_personal_information``)
- ``label`` and ``ask``: the plain reason and the question to ask when unknown

Each condition evaluates to ``"yes"``, ``"no"`` or ``"unknown"`` (three-valued logic).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

SYDNEY = ZoneInfo("Australia/Sydney")
DISCLAIMER = (
    "This is guidance, not legal advice. Nothing has been submitted, sent or lodged. "
    "A person decides and reports. Check each source before relying on it."
)
DRAFT_LABEL = "DRAFT. Not submitted."
_YES, _NO, _UNKNOWN = "yes", "no", "unknown"
_FROM_DISCOVERY = {"awareness", "belief", "payment_or_awareness"}
# How a clock origin that the engine cannot time is described to a person.
_ORIGIN_LABELS = {
    "belief": "awareness of reasonable grounds to believe there was an eligible data breach",
    "statement_prepared": "preparing the statement to the Commissioner",
}
# Fact names the engine reads. Others are ignored, so a typo shows up as an unknown.
FACTS = (
    "summary",
    "cyber_security_incident",
    "personal_information_involved",
    "serious_harm_ruled_out",
    "eligible_breach_believed",
    "soci_part_2b_applies",
    "significant_availability_impact",
    "relevant_impact",
    "ransomware_payment_made",
    "payment_at",
    "apra_material_incident",
    "apra_control_weakness",
    "notified_other_regulator",
    "significant_cyber_security_incident",
    "oral_report_at",
    "asset",
    "impact",
    "customer_impact",
    "systems_affected",
    "status",
    "information_kinds",
    "individuals_affected",
    "malware_variant",
    "vulnerabilities",
    "demand_amount",
    "demand_method",
    "payment_amount",
    "payment_method",
    "paid_by",
    "incident_started_at",
    "indicators",
    "control_weakness",
    "other_regulators",
)
_ORG_FIELDS = (
    "name",
    "sector",
    "size",
    "turnover",
    "regulators",
    "critical_infrastructure",
    "holds_personal_information",
)
_ORG_DEFAULTS = {
    "name": "",
    "sector": "general",
    "size": "medium",
    "turnover": "unknown",
    "regulators": [],
    "critical_infrastructure": False,
    "holds_personal_information": True,
}


def parse_time(value: object, label: str) -> tuple[datetime | None, str]:
    """An aware datetime in Australia/Sydney, and a note. Naive values are read as Sydney.

    A naive Sydney time that falls in the October gap or the April overlap has no single
    instant, so it is refused with a note asking for an offset.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None, f"{label} is not an ISO 8601 date-time"
    else:
        return None, f"{label} is not an ISO 8601 date-time"
    if parsed.tzinfo is not None:
        return parsed.astimezone(SYDNEY), ""
    early = parsed.replace(tzinfo=SYDNEY, fold=0)
    late = parsed.replace(tzinfo=SYDNEY, fold=1)
    round_trip = early.astimezone(UTC).astimezone(SYDNEY).replace(tzinfo=None)
    if round_trip != parsed:
        return None, (
            f"{label} {parsed.isoformat()} does not exist in Australia/Sydney "
            "because the clocks went forward. Give a UTC offset."
        )
    if early.utcoffset() != late.utcoffset():
        return None, (
            f"{label} {parsed.isoformat()} is ambiguous in Australia/Sydney "
            "because the clocks went back. Give a UTC offset."
        )
    return early, f"{label} had no offset and was read as Australia/Sydney"


def add_hours(start: datetime, hours: int) -> datetime:
    """Elapsed hours: add in UTC, then show in Sydney, so DST cannot shift the interval."""
    return (start.astimezone(UTC) + timedelta(hours=hours)).astimezone(SYDNEY)


def add_days(start: datetime, days: int) -> datetime:
    """Calendar days on the Sydney wall clock, keeping the local time of day."""
    local = start.astimezone(SYDNEY).replace(tzinfo=None) + timedelta(days=days)
    return _localise(local)


def add_business_days(start: datetime, days: int) -> datetime:
    """Weekdays on the Sydney wall clock. Public holidays are not skipped (conservative)."""
    local = start.astimezone(SYDNEY).replace(tzinfo=None)
    added = 0
    while added < days:
        local += timedelta(days=1)
        if local.weekday() < 5:
            added += 1
    return _localise(local)


def _localise(local: datetime) -> datetime:
    """Attach Sydney time to a wall clock value; a time in the spring gap moves forward."""
    aware = local.replace(tzinfo=SYDNEY)
    return aware.astimezone(UTC).astimezone(SYDNEY)


def fmt(moment: datetime | None) -> str | None:
    if moment is None:
        return None
    return moment.astimezone(SYDNEY).isoformat(timespec="seconds")


def normalise_org(org: object) -> tuple[dict, list[str]]:
    """The fields the engine reads from an ``org.yaml`` mapping or an ``OrgProfile``."""
    notes: list[str] = []
    if org is None:
        notes.append("no organisation profile was given; using sector-neutral defaults")
        data: dict = {}
    elif isinstance(org, dict):
        data = org
    elif hasattr(org, "to_dict"):
        data = org.to_dict()
    else:
        notes.append("organisation profile was not a mapping; using defaults")
        data = {}
    out = {}
    for key in _ORG_FIELDS:
        value = data.get(key, _ORG_DEFAULTS[key])
        if value is None:
            value = _ORG_DEFAULTS[key]
        if key == "regulators":
            if isinstance(value, str):
                value = [value]
            value = [str(item).strip().lower() for item in value or [] if str(item).strip()]
            value = [item for item in value if item != "none"]
        elif key in ("critical_infrastructure", "holds_personal_information"):
            value = bool(value)
        else:
            value = str(value).strip()
            if key != "name":
                value = value.lower()
        out[key] = value
    return out, notes


def normalise_facts(facts: object) -> tuple[dict, list[str]]:
    notes: list[str] = []
    if facts is None:
        return {}, notes
    if not isinstance(facts, dict):
        return {}, ["incident facts were not a mapping and were ignored"]
    unknown = sorted(str(key) for key in facts if key not in FACTS)
    if unknown:
        notes.append("ignored unknown incident facts: " + ", ".join(unknown))
    return {key: facts[key] for key in FACTS if key in facts and facts[key] is not None}, notes


def evaluate(condition: object, org: dict, facts: dict) -> tuple[str, list[str], list[str]]:
    """Return (result, reasons, questions). Reasons explain a yes or a no."""
    if not isinstance(condition, dict) or not condition:
        return _YES, [], []
    if "all" in condition:
        parts = [evaluate(item, org, facts) for item in condition["all"] or []]
        failed = [p for p in parts if p[0] == _NO]
        if failed:
            return _NO, [r for p in failed for r in p[1]], []
        unknown = [p for p in parts if p[0] == _UNKNOWN]
        reasons = [r for p in parts if p[0] == _YES for r in p[1]]
        if unknown:
            return _UNKNOWN, reasons, _dedupe(q for p in unknown for q in p[2])
        return _YES, reasons, []
    if "any" in condition:
        parts = [evaluate(item, org, facts) for item in condition["any"] or []]
        passed = [p for p in parts if p[0] == _YES]
        if passed:
            return _YES, passed[0][1], []
        unknown = [p for p in parts if p[0] == _UNKNOWN]
        if unknown:
            return _UNKNOWN, [], _dedupe(q for p in unknown for q in p[2])
        return _NO, [r for p in parts for r in p[1]], []
    return _leaf(condition, org, facts)


def _leaf(leaf: dict, org: dict, facts: dict) -> tuple[str, list[str], list[str]]:
    label = str(leaf.get("label") or "")
    ask = str(leaf.get("ask") or label)
    if "org" in leaf:
        value = org.get(str(leaf["org"]))
        if value in (leaf.get("unknown_values") or []):
            return _UNKNOWN, [], [ask]
    else:
        name = str(leaf.get("fact"))
        fallback = leaf.get("org_false_means_no")
        if name not in facts and fallback and org.get(str(fallback)) is False:
            return _NO, [f"no: {label} (org.yaml says {fallback} is false)"], []
        if name not in facts:
            missing = leaf.get("missing", "unknown")
            if missing == "false":
                return _NO, ["no: " + label], []
            if missing == "true":
                return _YES, [label + " (assumed until told otherwise)"], []
            return _UNKNOWN, [], [ask]
        value = facts[name]
    if _match(leaf, value):
        return _YES, [label], []
    return _NO, ["no: " + label], []


def _match(leaf: dict, value: object) -> bool:
    if "equals" in leaf:
        return value == leaf["equals"]
    if "in" in leaf:
        return value in leaf["in"]
    if "not_in" in leaf:
        return value not in leaf["not_in"]
    if "contains" in leaf:
        return isinstance(value, list) and leaf["contains"] in value
    return bool(value)


def _dedupe(items) -> list[str]:
    seen: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.append(item)
    return seen


def check(
    snapshot: dict,
    *,
    org: object,
    facts: object,
    discovered_at: object,
    now: object = None,
) -> dict:
    """Applicable obligations, deadlines, recipients, sources, draft fields and a timeline."""
    notes: list[str] = []
    org_view, org_notes = normalise_org(org)
    fact_view, fact_notes = normalise_facts(facts)
    notes.extend(org_notes + fact_notes)
    discovered, discovered_note = parse_time(discovered_at, "discovered_at")
    if discovered_note:
        notes.append(discovered_note)
    payment, payment_note = (None, "")
    if "payment_at" in fact_view:
        payment, payment_note = parse_time(fact_view["payment_at"], "payment_at")
        if payment_note:
            notes.append(payment_note)
    oral, oral_note = (None, "")
    if "oral_report_at" in fact_view:
        oral, oral_note = parse_time(fact_view["oral_report_at"], "oral_report_at")
        if oral_note:
            notes.append(oral_note)
    current = None
    if now is not None:
        current, now_note = parse_time(now, "now")
        if now_note and current is None:
            notes.append(now_note)

    rules = [row for row in (snapshot or {}).get("obligations") or [] if isinstance(row, dict)]
    by_id = {row.get("id"): row for row in rules}
    applicable: list[dict] = []
    possible: list[dict] = []
    not_applicable: list[dict] = []
    for row in rules:
        if row.get("kind") == "note":
            continue
        result, reasons, questions = evaluate(row.get("applies_when"), org_view, fact_view)
        if result == _NO:
            not_applicable.append(
                {
                    "id": row.get("id"),
                    "title": row.get("title"),
                    "why_not": reasons,
                    "watch_for": row.get("not_applicable_note") or "",
                }
            )
            continue
        record = _obligation(
            row, result, reasons, questions, org_view, fact_view, discovered, payment, oral
        )
        (applicable if result == _YES else possible).append(record)

    active = {item["id"] for item in applicable + possible}
    limited_use = [
        _note(row)
        for row in rules
        if row.get("kind") == "note" and set(row.get("applies_with") or []) & active
    ]
    _flag_soci_overlap(applicable + possible)
    _flag_cps234_after_oaic(applicable, possible)
    timeline = _timeline(applicable + possible, current)
    questions = _dedupe(q for item in possible for q in item["questions"])
    return {
        "disclaimer": DISCLAIMER,
        "submitted": False,
        "timezone": "Australia/Sydney",
        "discovered_at": fmt(discovered),
        "now": fmt(current),
        "organisation": org_view,
        "applicable": applicable,
        "possible": possible,
        "not_applicable": not_applicable,
        "limited_use": limited_use,
        "questions": questions,
        "timeline": timeline,
        "notes": notes,
        "snapshot_date": (snapshot or {}).get("retrieved_at"),
        "unknown_rule_links": sorted(
            str(link)
            for row in rules
            for link in row.get("applies_with") or []
            if link not in by_id
        ),
    }


def _obligation(
    row: dict,
    result: str,
    reasons: list[str],
    questions: list[str],
    org: dict,
    facts: dict,
    discovered: datetime | None,
    payment: datetime | None,
    oral: datetime | None,
) -> dict:
    return {
        "id": row.get("id"),
        "regime": row.get("regime"),
        "trigger": row.get("trigger"),
        "title": row.get("title"),
        "kind": row.get("kind"),
        "status": "applies" if result == _YES else "may apply",
        "why": reasons,
        "questions": questions,
        "recipient": row.get("recipient") or "",
        "channel": row.get("channel") or "",
        "citation": row.get("citation") or "",
        "source_url": row.get("source_url") or "",
        "guidance_url": row.get("guidance_url") or "",
        "related_sources": list(row.get("related_sources") or []),
        "last_reviewed": row.get("last_reviewed") or row.get("retrieved_at") or "",
        "verification": dict(row.get("verification") or {}),
        "deadlines": [_deadline(c, discovered, payment, oral) for c in row.get("clocks") or []],
        "draft": {
            "label": DRAFT_LABEL,
            "fields": [
                _field(item, org, facts, discovered) for item in row.get("report_fields") or []
            ],
            "note": row.get("field_note") or "",
        },
        "warnings": [],
    }


def _deadline(
    clock: dict, discovered: datetime | None, payment: datetime | None, oral: datetime | None
) -> dict:
    origin = clock.get("from") or ""
    start = None
    start_label = _ORIGIN_LABELS.get(origin, origin)
    if origin == "belief":
        # The clock runs from belief, which may come after discovery. No fixed hours.
        pass
    elif origin == "payment_or_awareness":
        start = payment or discovered
        start_label = "payment" if payment else "discovery (no payment time given)"
    elif origin in _FROM_DISCOVERY:
        start = discovered
        start_label = "discovery"
    elif origin == "oral_report":
        start = oral
        start_label = "oral report" if oral else "oral report (time not given)"
    hours, days, business = clock.get("hours"), clock.get("days"), clock.get("business_days")
    due = None
    if start is not None:
        if hours:
            due = add_hours(start, int(hours))
        elif days:
            due = add_days(start, int(days))
        elif business:
            due = add_business_days(start, int(business))
    if hours:
        span = f"{hours} hours"
    elif days:
        span = f"{days} days"
    elif business:
        span = f"{business} business days"
    else:
        span = "as soon as practicable"
    return {
        "name": clock.get("name") or "",
        "span": span,
        "from": start_label,
        "starts_at": fmt(start),
        "due_at": fmt(due),
        "basis": clock.get("basis") or "",
    }


def _field(item: dict, org: dict, facts: dict, discovered: datetime | None) -> dict:
    source = item.get("prefill")
    value = None
    if source == "discovered_at":
        value = fmt(discovered)
    elif isinstance(source, str) and source.startswith("org."):
        value = org.get(source[4:]) or None
    elif isinstance(source, str) and source.startswith("fact."):
        raw = facts.get(source[5:])
        value = None if raw is None else str(raw)
    return {
        "field": item.get("field") or "",
        "value": value if value not in ("", None) else None,
        "status": "prefilled draft" if value not in ("", None) else "to complete",
    }


def _note(row: dict) -> dict:
    return {
        "id": row.get("id"),
        "title": row.get("title"),
        "summary": row.get("rule") or "",
        "citation": row.get("citation") or "",
        "source_url": row.get("source_url") or "",
        "last_reviewed": row.get("last_reviewed") or "",
        "verification": dict(row.get("verification") or {}),
    }


def _flag_soci_overlap(items: list[dict]) -> None:
    ids = {item["id"]: item for item in items}
    critical = ids.get("soci.critical_incident")
    other = ids.get("soci.other_incident")
    if critical and other and critical["status"] == "applies":
        other["warnings"].append(
            "The 12 hour critical incident clock also applies. Meet the 12 hour deadline; "
            "do not wait for the 72 hour clock."
        )


def _flag_cps234_after_oaic(applicable: list[dict], possible: list[dict]) -> None:
    ids = {item["id"] for item in applicable + possible}
    if "ndb.eligible_breach" not in ids:
        return
    for item in applicable + possible:
        if item["id"] == "apra_cps234.material_incident":
            item["warnings"].append(
                "A statement to the OAIC is a notification to another regulator, which is "
                "itself a CPS 234 paragraph 35 trigger. Notify APRA within 72 hours of "
                "becoming aware of the incident."
            )


def _timeline(items: list[dict], now: datetime | None) -> list[dict]:
    rows = []
    for item in items:
        for deadline in item["deadlines"]:
            row = {
                "obligation": item["id"],
                "title": item["title"],
                "deadline": deadline["name"],
                "status": item["status"],
                "due_at": deadline["due_at"],
                "span": deadline["span"],
                "from": deadline["from"],
                "remaining": None,
                "overdue": None,
            }
            if deadline["due_at"] and now is not None:
                due = datetime.fromisoformat(deadline["due_at"])
                seconds = int((due.astimezone(UTC) - now.astimezone(UTC)).total_seconds())
                row["overdue"] = seconds < 0
                row["remaining"] = _duration(abs(seconds))
            rows.append(row)
    rows.sort(key=lambda r: (r["due_at"] is None, _utc_key(r["due_at"]), r["obligation"]))
    return rows


def _utc_key(value: str | None) -> str:
    if not value:
        return ""
    return datetime.fromisoformat(value).astimezone(UTC).isoformat()


def _duration(seconds: int) -> str:
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    parts.append(f"{hours}h")
    parts.append(f"{minutes:02d}m")
    return " ".join(parts)


def render_text(result: dict) -> str:
    """A plain text report a person can read. Includes the disclaimer and the draft label."""
    lines = [result["disclaimer"], ""]
    lines.append(f"Discovered: {result.get('discovered_at') or 'unknown'} (Australia/Sydney)")
    if result.get("now"):
        lines.append(f"Countdown as at: {result['now']}")
    lines.append("")
    lines.append("Timeline (soonest first):")
    if not result["timeline"]:
        lines.append("- No fixed deadline found.")
    for row in result["timeline"]:
        due = row["due_at"] or "as soon as practicable"
        left = ""
        if row["remaining"] is not None:
            if row["overdue"]:
                left = f" (OVERDUE by {row['remaining']})"
            else:
                left = f" ({row['remaining']} left)"
        lines.append(f"- {due}{left}: {row['title']}, {row['deadline']} [{row['status']}]")
    for heading, key in (("Applies", "applicable"), ("May apply", "possible")):
        lines.append("")
        lines.append(f"{heading}:")
        if not result[key]:
            lines.append("- None.")
        for item in result[key]:
            lines.append(f"- {item['title']} ({item['kind']})")
            lines.append(f"  Recipient: {item['recipient']}")
            lines.append(f"  Channel: {item['channel']}")
            for deadline in item["deadlines"]:
                due = deadline["due_at"] or "no fixed time"
                lines.append(
                    f"  Deadline {deadline['name']}: {deadline['span']} from "
                    f"{deadline['from']}, due {due}"
                )
                lines.append(f"    Basis: {deadline['basis']}")
            for warning in item["warnings"]:
                lines.append(f"  Warning: {warning}")
            for question in item["questions"]:
                lines.append(f"  Question: {question}")
            lines.append(f"  Citation: {item['citation']}. Link: {item['source_url']}")
            lines.append(
                f"  Source: {item['title']}, aureg snapshot {result.get('snapshot_date')}, "
                f"retrieved {item['last_reviewed']}"
            )
            if item["draft"]["fields"]:
                lines.append(f"  {item['draft']['label']} Draft fields:")
                for field in item["draft"]["fields"]:
                    value = field["value"] if field["value"] is not None else "(to complete)"
                    lines.append(f"    {field['field']}: {value}")
    if result["limited_use"]:
        lines.append("")
        lines.append("Limited use notes:")
        for note in result["limited_use"]:
            lines.append(
                f"- {note['title']}. Citation: {note['citation']}. Link: {note['source_url']}"
            )
            lines.append(f"  {note['summary']}")
    if result["not_applicable"]:
        lines.append("")
        lines.append("Does not apply on these facts:")
        for item in result["not_applicable"]:
            lines.append(f"- {item['title']}: {'; '.join(item['why_not'])}")
            if item["watch_for"]:
                lines.append(f"  Watch for: {item['watch_for']}")
    for note in result["notes"]:
        lines.append(f"Note: {note}")
    return "\n".join(lines) + "\n"
