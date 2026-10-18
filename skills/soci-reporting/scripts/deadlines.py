#!/usr/bin/env python3
"""SOCI Part 2B deadlines in Australia/Sydney.

Hour offsets are added to the UTC instant, then converted back to
Australia/Sydney. Adding the same number of hours on the Sydney wall clock
is wrong across a daylight saving transition.

This helper does not contact ASD or anyone else. It does not submit a report.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

SYDNEY = ZoneInfo("Australia/Sydney")
UTC = timezone.utc  # noqa: UP017 datetime.UTC needs Python 3.11; this helper also runs on 3.9

# report_hours run from awareness. written_record_hours run from the oral report.
TRIGGERS: dict[str, dict[str, str | int]] = {
    "critical_incident": {
        "section": "30BC",
        "report_hours": 12,
        "written_record_hours": 84,
    },
    "other_incident": {
        "section": "30BD",
        "report_hours": 72,
        "written_record_hours": 48,
    },
}


def parse_moment(value: str) -> datetime:
    """Parse an instant and express it in Australia/Sydney.

    A value with no offset is read as Sydney civil time. A time that falls in
    the October gap, or in the April overlap, is rejected so the caller has to
    supply an offset.
    """
    text = value.strip()
    if not text:
        raise ValueError("Provide an awareness time.")
    if "T" not in text and " " not in text:
        raise ValueError("Provide a time of day, not a date alone.")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"Could not parse {value!r} as a date-time.") from exc
    if parsed.tzinfo is None:
        return _attach_sydney(parsed)
    return parsed.astimezone(SYDNEY)


def add_hours(moment: datetime, hours: int) -> datetime:
    """Add ``hours`` in UTC, then convert the result to Australia/Sydney."""
    if moment.tzinfo is None:
        raise ValueError("moment must be timezone-aware")
    if hours < 0:
        raise ValueError("hours must be zero or positive")
    later = moment.astimezone(UTC) + timedelta(hours=hours)
    return later.astimezone(SYDNEY)


def format_sydney(moment: datetime) -> str:
    """Format an instant as Sydney local time with a numeric offset."""
    return moment.astimezone(SYDNEY).isoformat(timespec="seconds")


def compute_deadlines(
    trigger: str,
    aware_at: str,
    oral_at: str | None = None,
) -> dict[str, object]:
    """Return the report deadline and, when an oral time is known, the written record."""
    rule = TRIGGERS.get(trigger)
    if rule is None:
        allowed = ", ".join(sorted(TRIGGERS))
        raise ValueError(f"Unknown trigger {trigger!r}. Use one of: {allowed}.")
    aware = parse_moment(aware_at)
    report_hours = int(rule["report_hours"])
    written_hours = int(rule["written_record_hours"])
    oral_text = oral_at.strip() if isinstance(oral_at, str) else ""
    oral = parse_moment(oral_text) if oral_text else None
    if oral is not None and oral.astimezone(UTC) < aware.astimezone(UTC):
        raise ValueError("The oral report cannot be given before the entity became aware.")
    report_due = add_hours(aware, report_hours)
    return {
        "regime": "soci",
        "trigger": trigger,
        "section": rule["section"],
        "zone": "Australia/Sydney",
        "aware_at": format_sydney(aware),
        "report_hours": report_hours,
        "report_due": format_sydney(report_due),
        "written_record_hours": written_hours,
        "written_record_anchor": "oral_report",
        "oral_at": format_sydney(oral) if oral is not None else None,
        "oral_after_report_due": (
            oral.astimezone(UTC) > report_due.astimezone(UTC) if oral is not None else None
        ),
        "written_record_due": (
            format_sydney(add_hours(oral, written_hours)) if oral is not None else None
        ),
        "method": "add hours in UTC, then convert to Australia/Sydney",
    }


def _attach_sydney(naive: datetime) -> datetime:
    """Localise a naive civil time, rejecting gaps and folds."""
    if naive.tzinfo is not None:
        raise ValueError("expected a naive datetime")
    instants: dict[int, datetime] = {}
    for fold in (0, 1):
        candidate = naive.replace(tzinfo=SYDNEY, fold=fold)
        returned = candidate.astimezone(UTC).astimezone(SYDNEY)
        if returned.replace(tzinfo=None) != naive:
            continue
        instants.setdefault(int(candidate.timestamp()), candidate)
    shown = naive.isoformat(timespec="seconds")
    if not instants:
        raise ValueError(f"{shown} does not exist in Australia/Sydney. Provide an offset.")
    if len(instants) > 1:
        raise ValueError(f"{shown} is ambiguous in Australia/Sydney. Provide an offset.")
    return next(iter(instants.values()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compute SOCI Part 2B deadlines in Australia/Sydney."
    )
    parser.add_argument("--trigger", required=True, choices=sorted(TRIGGERS))
    parser.add_argument("--aware-at", required=True)
    parser.add_argument("--oral-at", default=None)
    args = parser.parse_args(argv)
    try:
        result = compute_deadlines(args.trigger, args.aware_at, args.oral_at)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
