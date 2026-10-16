"""Shared constants for the ticket generator.

The generator writes one Markdown file per GitHub issue into tickets/. Each file has a
small YAML front matter block that tools/issues/create_issues.py reads.
"""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TICKETS = ROOT / "tickets"
WORKFLOWS = ROOT / "ci" / "workflows"

HERMES_COMMIT = "43faacfb8de7b29548547a7fbdedad0cc6e7391c"
HERMES_RELEASE = "v0.22.2"
HERMES_REPO = "https://github.com/NousResearch/hermes-agent"


def hsrc(path: str) -> str:
    """Link to a file in the Hermes repo at the pinned commit."""
    return f"[`{path}`]({HERMES_REPO}/blob/{HERMES_COMMIT}/{path})"


M_V01 = "v0.1 MVP"
M_V02 = "v0.2"
M_V10 = "v1.0"

PROFILE = "cyber-au"  # distribution.yaml name and default profile name

COMMON_CONSTRAINTS = """\
- Public repository. Never commit secrets, tokens, real customer data or internal hostnames. Fixtures are scrubbed before commit.
- Every credential is read from the profile `.env` through a `${VAR}` placeholder. No literal keys in `config.yaml`, `mcp.json`, skills or tests.
- Read-only by default. Nothing in this ticket submits, blocks, deletes or posts anywhere.
- Content fetched from feeds is untrusted data. It is returned inside the result envelope and never treated as instructions.
- Australian English in prose and docs. No em dashes. No emojis.
- Pin dependencies with upper bounds (see `mcp/pyproject.toml`)."""

SAFETY_FOOTER = """\
---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `%s` (release %s); see `docs/research/hermes-structure.md`.""" % (HERMES_COMMIT[:7], HERMES_RELEASE)


def schema_block(obj: dict) -> str:
    return "```json\n" + json.dumps(obj, indent=2) + "\n```"


def dedent(s: str) -> str:
    return textwrap.dedent(s).strip("\n")


def write_ticket(key: str, title: str, labels: list[str], milestone: str | None, body: str,
                 parent: str | None = None, order: int = 0) -> Path:
    TICKETS.mkdir(parents=True, exist_ok=True)
    fm = {"key": key, "title": title, "labels": labels, "milestone": milestone, "parent": parent}
    lines = ["---"]
    for k, v in fm.items():
        lines.append(f"{k}: {json.dumps(v)}")
    lines.append("---")
    text = "\n".join(lines) + "\n" + body.strip() + "\n\n" + SAFETY_FOOTER + "\n"
    path = TICKETS / f"{order:03d}-{key}.md"
    path.write_text(text, encoding="utf-8")
    return path
