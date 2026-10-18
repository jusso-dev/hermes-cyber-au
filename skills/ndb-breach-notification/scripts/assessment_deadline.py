"""Sydney assessment window for a suspected eligible data breach.

Pure date arithmetic. No network and no clock reads unless the caller omits
``as_of``. The OAIC assessment period is 30 calendar days after the Sydney
day the entity became aware. The warning flag at seven days is operational
for this skill. It is not an OAIC rule.
"""

from __future__ import annotations

import json
import sys
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

SYDNEY = ZoneInfo("Australia/Sydney")
ASSESSMENT_DAYS = 30
WARNING_DAYS = 7


class DeadlineError(ValueError):
    """The awareness time or the as-of time could not be read."""


def assessment_window(aware_at: str, as_of: str | None = None) -> dict[str, object]:
    """Return the assessment deadline for one suspected breach.

    ``aware_at`` and ``as_of`` are ISO 8601 dates or datetimes. A date with no
    time is that calendar day in Australia/Sydney. A datetime must include an
    offset (``Z`` is read as UTC). The deadline is 30 calendar days after the
    Sydney awareness day, so it is date arithmetic and does not drift when
    daylight saving starts or ends. An ``aware_at`` after ``as_of`` is an error.
    """
    aware_day = sydney_day(aware_at, "aware_at")
    as_of_day = datetime.now(SYDNEY).date() if as_of is None else sydney_day(as_of, "as_of")
    if aware_day > as_of_day:
        raise DeadlineError("aware_at is after as_of; check the awareness date")
    deadline = aware_day + timedelta(days=ASSESSMENT_DAYS)
    remaining = (deadline - as_of_day).days
    overdue = remaining < 0
    return {
        "timezone": "Australia/Sydney",
        "aware_on": aware_day.isoformat(),
        "deadline_on": deadline.isoformat(),
        "as_of": as_of_day.isoformat(),
        "days_remaining": remaining,
        "warning": overdue or remaining <= WARNING_DAYS,
        "overdue": overdue,
        "rule": "30 calendar days after the Sydney day the entity became aware",
    }


def sydney_day(value: str, label: str) -> date:
    """Calendar day in Australia/Sydney for an ISO 8601 date or datetime."""
    text = value.strip()
    if not text:
        raise DeadlineError(f"{label} is empty")
    if len(text) == 10:
        try:
            return date.fromisoformat(text)
        except ValueError as exc:
            raise DeadlineError(f"{label} is not an ISO 8601 date or datetime") from exc
    if text[-1] in "Zz":
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise DeadlineError(f"{label} is not an ISO 8601 date or datetime") from exc
    if parsed.tzinfo is None:
        raise DeadlineError(f"{label} must include a timezone offset")
    return parsed.astimezone(SYDNEY).date()


def main(argv: list[str] | None = None) -> int:
    """Print one assessment window as JSON."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) not in (1, 2):
        print("usage: assessment_deadline.py <aware_at> [as_of]", file=sys.stderr)
        return 2
    try:
        window = assessment_window(args[0], args[1] if len(args) == 2 else None)
    except DeadlineError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(window, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
