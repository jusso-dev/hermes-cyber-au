"""Choose the ISM release in force on a calendar date. No network."""

from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path


def release_in_force(releases: list[dict], day: date) -> str | None:
    """Return the newest tag published on or before ``day``, or None."""
    best: tuple[date, str] | None = None
    for row in releases:
        if not isinstance(row, dict):
            continue
        tag = str(row.get("tag_name") or "")
        published = str(row.get("published_at") or "")
        if not tag or len(published) < 10:
            continue
        try:
            published_day = date.fromisoformat(published[:10])
        except ValueError:
            continue
        if published_day <= day and (best is None or published_day > best[0]):
            best = (published_day, tag)
    return None if best is None else best[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="release_in_force",
        description="Print the ISM release in force on a date.",
    )
    parser.add_argument("releases", type=Path)
    parser.add_argument("day", help="Calendar date, YYYY-MM-DD")
    args = parser.parse_args(argv)
    try:
        day = date.fromisoformat(args.day)
        payload = json.loads(args.releases.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        print("none")
        return 2
    rows = payload.get("releases") if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        print("none")
        return 2
    chosen = release_in_force(rows, day)
    print(chosen or "none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
