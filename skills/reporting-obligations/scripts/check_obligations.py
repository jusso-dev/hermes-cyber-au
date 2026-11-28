#!/usr/bin/env python3
"""Run the Australian reporting obligations checker offline.

Reads the reviewed obligations snapshot shipped in mcp/au-regulatory/data, an org.yaml
and a facts JSON file, and prints which reports may apply, Sydney deadlines, recipients,
sources, draft fields and a countdown timeline. Pure: no network, and it writes nothing.
It does not submit, send or lodge anything. This is guidance, not legal advice.

    python skills/reporting-obligations/scripts/check_obligations.py \\
        --discovered-at 2026-10-03T20:00:00+10:00 --facts facts.json --org org.yaml \\
        [--now 2026-10-04T06:00:00+11:00] [--json]

Use the same engine as the aureg_check tool. When the au-regulatory package is not on
the path, this script loads it from the checkout.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1]
ROOT = SKILL.parents[1]
PACKAGE_SRC = ROOT / "mcp" / "au-regulatory" / "src"
DATA = ROOT / "mcp" / "au-regulatory" / "data"


def _engine():
    try:
        from cyberau_au_regulatory import engine
    except ModuleNotFoundError:
        sys.path.insert(0, str(PACKAGE_SRC))
        from cyberau_au_regulatory import engine
    return engine


def load_snapshot(path: Path | None = None) -> dict:
    if path is None:
        found = sorted(DATA.glob("obligations-*.json"))
        if not found:
            raise FileNotFoundError("no obligations snapshot under mcp/au-regulatory/data")
        path = found[-1]
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_org(path: str | None) -> dict | None:
    if not path:
        return None
    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml
    except ModuleNotFoundError:
        return json.loads(text)
    data = yaml.safe_load(text)
    if data is not None and not isinstance(data, dict):
        raise ValueError("org file must be a mapping")
    return data


def load_facts(path: str | None) -> dict:
    if not path:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("facts file must be a JSON object")
    return data


def run(
    discovered_at: str,
    facts: dict,
    org: dict | None,
    now: str | None = None,
    snapshot: dict | None = None,
) -> dict:
    return _engine().check(
        snapshot if snapshot is not None else load_snapshot(),
        org=org,
        facts=facts,
        discovered_at=discovered_at,
        now=now,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--discovered-at", required=True)
    parser.add_argument("--facts", help="JSON file of incident facts")
    parser.add_argument("--org", help="org.yaml (or JSON) organisation profile")
    parser.add_argument("--now", help="count down from this time")
    parser.add_argument("--snapshot", help="obligations snapshot JSON (default: shipped)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = parser.parse_args(argv)
    try:
        snapshot = load_snapshot(Path(args.snapshot) if args.snapshot else None)
        result = run(
            args.discovered_at,
            load_facts(args.facts),
            load_org(args.org),
            args.now,
            snapshot,
        )
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(_engine().render_text(result), end="")
    return 0 if result["discovered_at"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
