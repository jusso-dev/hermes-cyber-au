#!/usr/bin/env python3
"""House style for docs pages: no em dashes, no emojis, owner and date."""

from __future__ import annotations

import re
import sys
import unicodedata
from pathlib import Path

DOCS = Path(__file__).resolve().parents[2] / "docs"
EM_DASH = "\u2014"
OWNER = re.compile(r"^Owner ticket: [a-z0-9-]+$")
VERIFIED = re.compile(
    r"^Last verified: \d{1,2} "
    r"(January|February|March|April|May|June|July|August|"
    r"September|October|November|December) \d{4}$"
)


def emoji_chars(text: str) -> list[str]:
    found: list[str] = []
    for char in text:
        code = ord(char)
        if (
            0x1F300 <= code <= 0x1FAFF
            or 0x1F1E6 <= code <= 0x1F1FF
            or 0x2600 <= code <= 0x27BF
            or 0xFE00 <= code <= 0xFE0F
            or code in {0x200D, 0x20E3}
        ):
            found.append(char)
            continue
        name = unicodedata.name(char, "")
        if "EMOJI" in name:
            found.append(char)
    return found


def main() -> int:
    errors: list[str] = []
    pages = sorted(DOCS.rglob("*.md"))
    if not pages:
        print("no docs pages found", file=sys.stderr)
        return 1
    for path in pages:
        rel = path.relative_to(DOCS.parent)
        lines = path.read_text(encoding="utf-8").splitlines()
        if not any(OWNER.match(line) for line in lines):
            errors.append(f"{rel}: missing owner ticket")
        if not any(VERIFIED.match(line) for line in lines):
            errors.append(f"{rel}: missing last-verified date")
        for number, line in enumerate(lines, 1):
            if EM_DASH in line or "&mdash;" in line or "&#8212;" in line:
                errors.append(f"{rel}:{number}: em dash")
            marks = emoji_chars(line)
            if marks:
                errors.append(f"{rel}:{number}: emoji")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"style check passed ({len(pages)} pages)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
