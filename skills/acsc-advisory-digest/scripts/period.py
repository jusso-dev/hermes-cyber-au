"""Window for the ACSC advisory digest. No network and no clock."""

from __future__ import annotations

from datetime import date, timedelta


def since_date(watermark: date) -> date:
    """Return the first day after an inclusive watermark."""
    return watermark + timedelta(days=1)


def proposed_watermark(*, today: date, fetch_ok: bool, previous: date) -> date | None:
    """Return the new inclusive watermark, or None when it must stay put.

    A failed, timed out, or stale fetch returns None. A successful fetch,
    including one with no new items, returns ``today``.
    """
    if not fetch_ok or today < previous:
        return None
    return today
