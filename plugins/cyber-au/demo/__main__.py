"""Run demo mode from a checkout with only Python 3.11 or newer.

    python3 plugins/cyber-au/demo triage
    python3 plugins/cyber-au/demo prompts

No connector packages, Hermes or model are needed for ``triage`` and ``prompts``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__:
    from . import add_parser, dispatch
else:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from demo import add_parser, dispatch  # type: ignore[no-redef]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyber-au")
    add_parser(parser.add_subparsers(dest="command", required=True))
    args = parser.parse_args(["demo", *(sys.argv[1:] if argv is None else argv)])
    return dispatch(args)


if __name__ == "__main__":
    raise SystemExit(main())
