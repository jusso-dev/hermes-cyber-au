#!/usr/bin/env python3
"""Walk an incident playbook and keep an append-only timeline. Standard library only.

    playbook.py list
    playbook.py show ransomware [--phase 2]
    playbook.py log TIMELINE.jsonl --playbook ransomware --phase 1 --who "Incident lead" \\
        --event "Ransom note found on FS01" [--at 2026-10-03T20:05:00+10:00] [--evidence E1] \\
        [--kind event|decision|proposal|approval|evidence]
    playbook.py timeline TIMELINE.jsonl

``log`` appends one JSON line to a file the user names. It never rewrites or deletes an
entry: a correction is a new entry. Times are Australia/Sydney with an offset. A time with
no offset is read as Sydney; one that falls in a daylight saving gap or overlap is refused.

This helper does not contact, send, block, isolate or submit anything. A ``proposal``
entry records what the assistant proposed; only an ``approval`` entry with a named person
records that someone approved it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

SYDNEY = ZoneInfo("Australia/Sydney")
UTC = timezone.utc  # noqa: UP017 datetime.UTC needs Python 3.11; this helper also runs on 3.9
ROOT = Path(__file__).resolve().parents[3]
PLAYBOOKS = ROOT / "playbooks"
SECTIONS = (
    "Scope",
    "Roles",
    "Approval boundaries",
    "Phases",
    "Evidence to collect",
    "Who to tell",
    "Reporting obligations",
    "Timeline record",
)
PHASES = (
    "Detect and triage",
    "Contain",
    "Investigate",
    "Eradicate and recover",
    "Notify and report",
    "Review",
)
KINDS = ("event", "decision", "proposal", "approval", "evidence")
_H2 = re.compile(r"^## (.+)$", re.M)
_H3 = re.compile(r"^### (\d+)\. (.+)$", re.M)


class PlaybookError(ValueError):
    """A playbook or a timeline entry cannot be used."""


def playbook_ids(directory: Path = PLAYBOOKS) -> list[str]:
    return sorted(p.stem for p in directory.glob("*.md") if p.name != "README.md")


def load(playbook_id: str, directory: Path = PLAYBOOKS) -> dict:
    if not re.fullmatch(r"[a-z0-9-]+", playbook_id or ""):
        raise PlaybookError("playbook id is lowercase words joined by hyphens")
    path = directory / f"{playbook_id}.md"
    if not path.is_file():
        raise PlaybookError(f"no playbook {playbook_id!r}; try: {', '.join(playbook_ids())}")
    text = path.read_text(encoding="utf-8")
    title = text.splitlines()[0].lstrip("# ").strip()
    sections = _split(text, _H2)
    phases = []
    for number, name, body in _split_numbered(sections.get("Phases", "")):
        phases.append({"number": number, "name": name, "body": body.strip()})
    return {
        "id": playbook_id,
        "title": title,
        "sections": {k: v.strip() for k, v in sections.items()},
        "phases": phases,
    }


def problems(playbook: dict) -> list[str]:
    """Structure problems: missing sections, phases or required phase parts."""
    found = []
    order = list(playbook["sections"])
    if order[: len(SECTIONS)] != list(SECTIONS):
        found.append(f"{playbook['id']}: sections must be {', '.join(SECTIONS)}")
    names = [p["name"] for p in playbook["phases"]]
    if names != list(PHASES):
        found.append(f"{playbook['id']}: phases must be {', '.join(PHASES)}")
    for phase in playbook["phases"]:
        if "Steps:" not in phase["body"]:
            found.append(f"{playbook['id']}: phase {phase['number']} has no steps")
        if phase["name"] != "Review" and "Decisions:" not in phase["body"]:
            found.append(f"{playbook['id']}: phase {phase['number']} has no decisions")
    boundaries = playbook["sections"].get("Approval boundaries", "")
    if "named person" not in boundaries or "Proposal:" not in boundaries:
        found.append(f"{playbook['id']}: approval boundaries must name a person and a proposal")
    reporting = playbook["sections"].get("Reporting obligations", "")
    if "reporting-obligations/SKILL.md" not in reporting:
        found.append(f"{playbook['id']}: reporting section must link the obligations checker")
    if "- [ ]" not in playbook["sections"].get("Evidence to collect", ""):
        found.append(f"{playbook['id']}: evidence section needs a checklist")
    return found


def _split(text: str, pattern: re.Pattern) -> dict[str, str]:
    matches = list(pattern.finditer(text))
    out: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        out[match.group(1).strip()] = text[match.end() : end]
    return out


def _split_numbered(text: str) -> list[tuple[int, str, str]]:
    matches = list(_H3.finditer(text))
    out = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        out.append((int(match.group(1)), match.group(2).strip(), text[match.end() : end]))
    return out


def parse_moment(value: str) -> datetime:
    text = (value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise PlaybookError(f"{value!r} is not an ISO 8601 date-time") from exc
    if parsed.tzinfo is not None:
        return parsed.astimezone(SYDNEY)
    early = parsed.replace(tzinfo=SYDNEY, fold=0)
    late = parsed.replace(tzinfo=SYDNEY, fold=1)
    if early.astimezone(UTC).astimezone(SYDNEY).replace(tzinfo=None) != parsed:
        raise PlaybookError(f"{value} does not exist in Australia/Sydney; give a UTC offset")
    if early.utcoffset() != late.utcoffset():
        raise PlaybookError(f"{value} is ambiguous in Australia/Sydney; give a UTC offset")
    return early


def entry(
    *,
    playbook: str,
    phase: int,
    who: str,
    event: str,
    at: str | None = None,
    kind: str = "event",
    evidence: list[str] | None = None,
    now: datetime | None = None,
) -> dict:
    """Validate and build one timeline entry. Does not write anything."""
    book = load(playbook)
    numbers = {p["number"]: p["name"] for p in book["phases"]}
    if phase not in numbers:
        raise PlaybookError(f"phase must be one of {sorted(numbers)}")
    if kind not in KINDS:
        raise PlaybookError(f"kind must be one of {', '.join(KINDS)}")
    if not (who or "").strip():
        raise PlaybookError("who is required: name the person or role")
    if not (event or "").strip():
        raise PlaybookError("event is required")
    if kind == "approval" and (who or "").strip().lower() in {"assistant", "hermes", "agent"}:
        raise PlaybookError("an approval must be recorded by a named person, not the assistant")
    moment = parse_moment(at) if at else (now or datetime.now(UTC)).astimezone(SYDNEY)
    return {
        "at": moment.isoformat(timespec="seconds"),
        "playbook": playbook,
        "phase": phase,
        "phase_name": numbers[phase],
        "kind": kind,
        "who": who.strip(),
        "event": " ".join(event.split()),
        "evidence": [item.strip() for item in evidence or [] if item.strip()],
    }


def append(path: Path, record: dict) -> None:
    """Append one JSON line. Never rewrites the file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def read_timeline(path: Path) -> list[dict]:
    rows = []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise PlaybookError(f"line {number} of the timeline is not JSON") from exc
    return rows


def render_timeline(rows: list[dict]) -> str:
    """Chronological table. Ties keep the order they were logged."""
    ordered = sorted(
        enumerate(rows),
        key=lambda pair: (parse_moment(pair[1]["at"]).astimezone(UTC), pair[0]),
    )
    lines = [
        "| Time (Australia/Sydney) | Phase | Kind | Who | Event | Evidence |",
        "|---|---|---|---|---|---|",
    ]
    for _, row in ordered:
        evidence = ", ".join(row.get("evidence") or []) or ""
        phase = f"{row['phase']}. {row['phase_name']}"
        cells = [row["at"], phase, row["kind"], row["who"], row["event"], evidence]
        lines.append("| " + " | ".join(c.replace("|", "/") for c in cells) + " |")
    pending = _pending_proposals(rows)
    if pending:
        lines.append("")
        lines.append("Proposals with no approval entry yet:")
        lines.extend(f"- {row['at']}: {row['event']}" for row in pending)
    return "\n".join(lines) + "\n"


def _pending_proposals(rows: list[dict]) -> list[dict]:
    approved = " ".join(r["event"].lower() for r in rows if r["kind"] == "approval")
    return [r for r in rows if r["kind"] == "proposal" and r["event"].lower() not in approved]


def elapsed(rows: list[dict]) -> timedelta | None:
    if not rows:
        return None
    times = [parse_moment(r["at"]).astimezone(UTC) for r in rows]
    return max(times) - min(times)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    show = sub.add_parser("show")
    show.add_argument("playbook")
    show.add_argument("--phase", type=int)
    log = sub.add_parser("log")
    log.add_argument("timeline", type=Path)
    log.add_argument("--playbook", required=True)
    log.add_argument("--phase", type=int, required=True)
    log.add_argument("--who", required=True)
    log.add_argument("--event", required=True)
    log.add_argument("--at")
    log.add_argument("--kind", default="event", choices=KINDS)
    log.add_argument("--evidence", action="append", default=[])
    timeline = sub.add_parser("timeline")
    timeline.add_argument("timeline", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "list":
            for playbook_id in playbook_ids():
                print(f"{playbook_id}: {load(playbook_id)['title']}")
        elif args.command == "show":
            book = load(args.playbook)
            if args.phase is None:
                print(f"# {book['title']}")
                for phase in book["phases"]:
                    print(f"{phase['number']}. {phase['name']}")
            else:
                phase = next((p for p in book["phases"] if p["number"] == args.phase), None)
                if phase is None:
                    raise PlaybookError("no such phase")
                print(f"### {phase['number']}. {phase['name']}\n\n{phase['body']}")
        elif args.command == "log":
            record = entry(
                playbook=args.playbook,
                phase=args.phase,
                who=args.who,
                event=args.event,
                at=args.at,
                kind=args.kind,
                evidence=args.evidence,
            )
            append(args.timeline, record)
            print(json.dumps(record, sort_keys=True))
        else:
            print(render_timeline(read_timeline(args.timeline)), end="")
    except (PlaybookError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
