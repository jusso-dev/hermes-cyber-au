#!/usr/bin/env python3
"""House style for docs pages: no em dashes, no emojis, owner and date."""

from __future__ import annotations

import re
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
EM_DASHES = "\u2014\u2015\u2e3a\u2e3b\ufe58"
EM_DASH_ENTITIES = re.compile(r"&(mdash|horbar|#0*8212|#0*8213|#x0*2014|#x0*2015);", re.IGNORECASE)
TICKET_KEY = re.compile(r'^key: "([a-z0-9-]+)"$', re.MULTILINE)
OWNER_LINE = re.compile(r"^Owner ticket: ([a-z0-9-]+)$")
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
            0x1F000 <= code <= 0x1FAFF
            or 0x231A <= code <= 0x231B
            or 0x23E9 <= code <= 0x23F3
            or 0x23F8 <= code <= 0x23FA
            or 0x2600 <= code <= 0x27BF
            or 0x2934 <= code <= 0x2935
            or 0x2B05 <= code <= 0x2B07
            or 0x2B1B <= code <= 0x2B1C
            or code in {0x2B50, 0x2B55, 0x3030, 0x303D, 0x3297, 0x3299}
            or 0xFE00 <= code <= 0xFE0F
            or code in {0x200D, 0x20E3}
        ):
            found.append(char)
            continue
        name = unicodedata.name(char, "")
        if "EMOJI" in name:
            found.append(char)
    return found


def ticket_keys() -> set[str]:
    keys: set[str] = set()
    for path in (ROOT / "tickets").glob("*.md"):
        match = TICKET_KEY.search(path.read_text(encoding="utf-8"))
        if match:
            keys.add(match.group(1))
    return keys


def missing_connector_pages() -> list[str]:
    """A connector with a SOURCE.md needs a page that the connectors index links."""
    errors: list[str] = []
    index = DOCS / "connectors" / "index.md"
    index_text = index.read_text(encoding="utf-8") if index.exists() else ""
    for source in sorted((ROOT / "mcp").glob("*/SOURCE.md")):
        name = source.parent.name
        page = DOCS / "connectors" / f"{name}.md"
        if not page.exists():
            errors.append(f"docs/connectors/{name}.md: missing page for mcp/{name}/SOURCE.md")
        elif f"({name}.md)" not in index_text:
            errors.append(f"docs/connectors/index.md: no link to {name}.md")
    return errors


def main() -> int:
    errors: list[str] = missing_connector_pages()
    keys = ticket_keys()
    pages = sorted(DOCS.rglob("*.md"))
    if not pages:
        print("no docs pages found", file=sys.stderr)
        return 1
    for path in pages:
        rel = path.relative_to(DOCS.parent)
        lines = path.read_text(encoding="utf-8").splitlines()
        owners = [m.group(1) for line in lines if (m := OWNER_LINE.match(line))]
        if not owners:
            errors.append(f"{rel}: missing owner ticket")
        elif owners[0] not in keys:
            errors.append(f"{rel}: owner ticket {owners[0]} has no file in tickets/")
        if not any(VERIFIED.match(line) for line in lines):
            errors.append(f"{rel}: missing last-verified date")
        for number, line in enumerate(lines, 1):
            if any(char in line for char in EM_DASHES) or EM_DASH_ENTITIES.search(line):
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
