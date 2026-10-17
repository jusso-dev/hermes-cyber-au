"""Window for the ACSC advisory digest. No network and no clock."""

from __future__ import annotations

from datetime import date, timedelta


def since_date(watermark: date) -> date:
    """Return the first day after an inclusive watermark."""
    return watermark + timedelta(days=1)


def proposed_watermark(*, today: date, fetch_ok: bool, previous: date) -> date | None:
    """Return the new inclusive watermark, or None when it must stay put.

    The feed ``since`` filter works on whole days, so the watermark is the last
    complete day, which is yesterday. Items published later today then appear in
    the next digest instead of being skipped. A failed, timed out, stale, or
    truncated fetch returns None, as does a result that would move the
    watermark backwards. A successful fetch, including one with no new items,
    returns yesterday.
    """
    candidate = today - timedelta(days=1)
    if not fetch_ok or candidate < previous:
        return None
    return candidate
