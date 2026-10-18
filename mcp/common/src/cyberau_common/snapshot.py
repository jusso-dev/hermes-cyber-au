"""Rules for data a connector ships under ``mcp/<connector>/data/``.

A shipped snapshot is the last rung of a connector's fallback ladder. It must be
real upstream data with a data date, and it is only served while that date is
inside the connector's maximum age. Synthetic test fixtures live under
``mcp/<connector>/tests/fixtures/`` and are never served at runtime.

When live, cached and shipped data are all missing or refused, a connector
returns an empty result with an ``unavailable`` warning instead of rows.
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime
from pathlib import Path

# Phrases that mark a file as a test fixture rather than a real publication. A bare
# "synthetic" is not enough: real guidance has headings such as "Synthetic
# impersonation" and talks about synthetic voice and video.
SYNTHETIC_MARKERS = re.compile(
    r"SYNTHETIC TEST|synthetic (?:fixture|test|data\b|record|sample|snapshot)|"
    r"synthetic[-_][a-z0-9]|"
    r"synthetic (?:advisory|alert|publication|threat|indicator|collection|"
    r"leak|note|summary|edge|acsc|cyber|demonstration|write-only|ip\b|domain\b|post|"
    r"[a-z]+ (?:alert|advisory|indicator|text))|"
    r"synthetic\.example|sample pty|sample council|invented for tests|"
    r"for (?:parser |search )?tests\b|trimmed fixture|not an? (?:ASD|AusCERT|CTIS) "
    r"(?:publication|collection)|example (?:widget|bank)\b",
    re.IGNORECASE,
)
_DAY = re.compile(r"(\d{4})-(\d{2})-(\d{2})")


def synthetic_marker(text: str) -> str | None:
    """Return the first synthetic marker in ``text``, or None when there is none."""
    match = SYNTHETIC_MARKERS.search(text or "")
    return match.group(0) if match else None


def parse_day(value: object) -> date | None:
    """Read the YYYY-MM-DD at the start of a date or timestamp string."""
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    match = _DAY.match(str(value or "").strip())
    if not match:
        return None
    try:
        return date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except ValueError:
        return None


def snapshot_problem(
    as_of: object, *, max_age_days: int, label: str, today: date | None = None
) -> str:
    """Return why a shipped snapshot must not be served, or "" when it may be."""
    day = parse_day(as_of)
    if day is None:
        return f"the shipped {label} snapshot has no data date, so it was not served"
    now = today or datetime.now(UTC).date()
    age = (now - day).days
    if age > max_age_days:
        return (
            f"the shipped {label} snapshot is dated {day.isoformat()}, {age} days old, "
            f"past the {max_age_days} day limit, so it was not served"
        )
    if age < -1:
        return f"the shipped {label} snapshot is dated in the future, so it was not served"
    return ""


def snapshot_note(label: str, as_of: object) -> str:
    """Warning attached to every envelope answered from a shipped snapshot."""
    day = parse_day(as_of)
    when = day.isoformat() if day else "an unknown date"
    return (
        f"served the shipped {label} snapshot dated {when}, not a live fetch. "
        "Check the source before relying on it"
    )


def unavailable(label: str, reason: str = "") -> str:
    """Warning for a source with no live, cached or real shipped data."""
    reason = reason.strip().rstrip(".")
    tail = f": {reason}" if reason else ""
    return f"{label} is unavailable{tail}. No live, cached or shipped data was served"


def check_shipped(
    text: str, as_of: object, *, label: str, max_age_days: int, today: date | None = None
) -> str:
    """Refuse synthetic or expired shipped text. Return "" when it may be served."""
    marker = synthetic_marker(text)
    if marker:
        return (
            f"the shipped {label} snapshot looks like test data ({marker!r}), so it was not served"
        )
    return snapshot_problem(as_of, max_age_days=max_age_days, label=label, today=today)


def read_shipped(path: Path) -> str | None:
    """Read a shipped file, or None when it is missing or unreadable."""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
