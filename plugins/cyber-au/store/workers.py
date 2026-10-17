"""Process entry points used by the concurrent writer test."""

from __future__ import annotations

import traceback


def write_distinct(path: str, prefix: str, count: int) -> None:
    """Insert ``count`` distinct domains for one writer."""
    try:
        from .api import upsert_indicator

        for index in range(count):
            upsert_indicator(
                "domain",
                f"{prefix}{index}.example",
                source=f"writer-{prefix}",
                observed_at="2026-02-02T00:00:00Z",
                raw=f"{prefix}:{index}".encode(),
                verdict="malicious",
                confidence=80,
                path=path,
            )
    except Exception:
        traceback.print_exc()
        raise


def write_same(path: str, prefix: str, count: int) -> None:
    """Append observations to one shared address."""
    try:
        from .api import upsert_indicator

        for index in range(count):
            day = (index % 27) + 1
            upsert_indicator(
                "ipv4",
                "203.0.113.10",
                source=f"writer-{prefix}",
                observed_at=f"2026-03-{day:02d}T00:00:00Z",
                raw=f"{prefix}:{index}".encode(),
                verdict="suspicious",
                confidence=60,
                path=path,
            )
    except Exception:
        traceback.print_exc()
        raise


def open_fresh(path: str, barrier, results) -> None:
    """Open a new database at the same moment as the other writers."""
    from .db import open_store

    barrier.wait(30)
    try:
        open_store(path).connection()
        results.put("ok")
    except Exception as exc:
        results.put(f"{type(exc).__name__}: {exc}")
