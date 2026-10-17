"""cyberau watchlist and exposure-watch commands."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cyberau_org_exposure.service import run_exposure_watch
from cyberau_org_exposure.watchlist import (
    WatchlistError,
    default_watchlist_path,
    init_org_watchlist,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyberau")
    sub = parser.add_subparsers(dest="command", required=True)

    watchlist = sub.add_parser("watchlist")
    watch_sub = watchlist.add_subparsers(dest="action", required=True)
    init = watch_sub.add_parser("init")
    init.add_argument("--org", action="store_true")
    init.add_argument("--path")

    run = sub.add_parser("exposure-watch")
    run.add_argument("--since")

    args = parser.parse_args(argv)
    if args.command == "watchlist":
        return _init(args)
    result = run_exposure_watch(since=args.since)
    print(json.dumps(result, indent=2, sort_keys=True))
    data = result["query"].get("data") or {}
    if data.get("sent") is False and not result["alerts"]:
        return 1
    return 0


def _init(args) -> int:
    if not args.org:
        print(
            "Only --org is supported. This creates your org exposure watchlist on this machine.",
            file=sys.stderr,
        )
        return 2
    path = Path(args.path) if args.path else default_watchlist_path()
    try:
        init_org_watchlist(path)
    except WatchlistError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"Created {path}. Edit it for your own organisation before running a search.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
