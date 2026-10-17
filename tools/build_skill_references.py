"""Write skill reference files and a pull request body from local data directories."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cyberau_common.regen import render_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build_skill_references")
    parser.add_argument("--write", required=True)
    parser.add_argument("--root", default=".")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    destination = Path(args.write)
    if not destination.is_absolute():
        destination = root / destination
    if not root.is_dir():
        print(f"root is absent: {args.root}", file=sys.stderr)
        return 2
    text = render_report(root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")
    print(f"Wrote {destination.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
