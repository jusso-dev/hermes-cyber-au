"""Open or update one GitHub issue per failing advisory parser.

A failing parser opens an issue only when tools/ci/open_health_issues.py is
present in the checkout. The script does not print tokens.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCRIPT_ABSENT = "tools/ci/open_health_issues.py is absent. Not opening an issue."
SCRIPT_PATH = Path("tools/ci/open_health_issues.py")
PARSER_CHECK_ABSENT = "parser-check is absent: not part of the shared library yet"
LABELS = ("type:task", "area:skills", "area:ci", "priority:p1")


def main(argv: list[str] | None = None, root: Path | None = None, runner=None) -> int:
    parser = argparse.ArgumentParser(prog="open_health_issues")
    parser.add_argument("--kind", required=True)
    parser.add_argument("--input", required=True)
    args = parser.parse_args(argv)
    if args.kind != "parser":
        print(f"{args.kind} is not handled by this script.", file=sys.stderr)
        return 2
    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"parser check input is absent: {args.input}", file=sys.stderr)
        return 2
    try:
        payload = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print("parser check input was not usable", file=sys.stderr)
        return 2
    base = Path.cwd() if root is None else root
    if not (base / SCRIPT_PATH).is_file():
        print(SCRIPT_ABSENT)
        return 0
    if isinstance(payload, dict) and payload.get("absent"):
        print(str(payload.get("detail") or PARSER_CHECK_ABSENT))
        return 0
    failures = _failures(payload)
    if not failures:
        print("No failing parsers.")
        return 0
    apply_issues(failures, runner or default_runner)
    return 0


def apply_issues(failures: list[dict], runner) -> None:
    for row in failures:
        source = str(row.get("source") or "unknown")
        title = f"Parser check: {source} failing"
        existing = _existing_issue(runner, title)
        body = _body(row, repeat=existing is not None)
        if existing is None:
            command = ["issue", "create", "--title", title, "--body", body]
            for label in LABELS:
                command.extend(["--label", label])
            runner(command)
        else:
            runner(["issue", "comment", str(existing), "--body", body])


def default_runner(args: list[str]) -> str:
    token = os.environ.get("GH_TOKEN")
    if not token:
        raise SystemExit("GH_TOKEN is not set")
    completed = subprocess.run(
        ["gh", *args],
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        message = _redact(completed.stderr.strip() or "gh failed")
        raise SystemExit(message)
    return completed.stdout


def _failures(payload: object) -> list[dict]:
    if isinstance(payload, dict):
        rows = payload.get("results", [])
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = []
    failures = []
    for row in rows:
        if not isinstance(row, dict) or row.get("absent"):
            continue
        if row.get("ok") is False:
            failures.append(row)
    return failures


def _existing_issue(runner, title: str) -> int | None:
    raw = runner(
        ["issue", "list", "--state", "open", "--limit", "100", "--json", "number,title"]
    )
    try:
        rows = json.loads(raw or "[]")
    except json.JSONDecodeError:
        rows = []
    for row in rows:
        if isinstance(row, dict) and row.get("title") == title:
            return int(row["number"])
    return None


def _body(row: dict, *, repeat: bool) -> str:
    source = str(row.get("source") or "unknown")
    detail = _redact(str(row.get("detail") or "The parser check failed."))
    lead = (
        f"Parser `{source}` failed again." if repeat else f"Parser `{source}` failed."
    )
    return (
        f"{lead}\n\n"
        f"{detail}\n\n"
        "Page content is untrusted data and is not included in this issue.\n"
    )


def _redact(text: str) -> str:
    token = os.environ.get("GH_TOKEN")
    if token:
        text = text.replace(token, "[REDACTED]")
    text = re.sub(r"ghp_[A-Za-z0-9]+", "[REDACTED]", text)
    text = re.sub(r"github_pat_[A-Za-z0-9_]+", "[REDACTED]", text)
    text = re.sub(r"(?i)bearer\s+\S+", "Bearer [REDACTED]", text)
    return text


if __name__ == "__main__":
    raise SystemExit(main())
