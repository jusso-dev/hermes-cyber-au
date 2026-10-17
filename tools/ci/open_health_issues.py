"""Open, update or close connector health issues from a health report.

One issue per broken connector, titled ``Connector health: <key> failing``.
A repeat failure comments on that issue. Recovery closes it with a comment.
Connectors that were not checked are left alone. Response bodies are never
copied into the issue, and keyed connectors do not contribute free-text detail.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

LABELS = ["type:task", "area:connectors", "priority:p1", "connector-health"]
_LAST_GOOD = re.compile(r"^Last good: (\d{4}-\d{2}-\d{2})$", re.MULTILINE)
_FIELD = re.compile(r"^[A-Za-z0-9_.-]{1,120}$")
_KEY = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
_ERROR = re.compile(r"[A-Za-z0-9_]{1,40}")
_TYPES = {"string", "number", "integer", "boolean", "object", "array", "null"}
_HIDDEN = {"body", "response", "payload", "raw", "text", "content"}


def main(argv: list[str] | None = None, *, client=None) -> int:
    parser = argparse.ArgumentParser(
        description="Open, update or close connector health issues."
    )
    parser.add_argument("--kind", required=True)
    parser.add_argument("--input", required=True, dest="input_path")
    parser.add_argument("--close-recovered", action="store_true")
    args = parser.parse_args(argv)
    if args.kind != "connector":
        print("kind must be connector", file=sys.stderr)
        return 2
    path = Path(args.input_path)
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        print("health report not found", file=sys.stderr)
        return 2
    except json.JSONDecodeError:
        print("health report is not valid JSON", file=sys.stderr)
        return 2
    if not isinstance(report, dict) or not isinstance(report.get("connectors"), list):
        print("health report is missing connectors", file=sys.stderr)
        return 2
    github = client or GhCli()
    failures = sync(report, github, close_recovered=args.close_recovered)
    for message in failures:
        print(message, file=sys.stderr)
    return 1 if failures else 0


def sync(report: dict, github, *, close_recovered: bool) -> list[str]:
    """Update issues for every connector. Returns one message per connector that failed.

    A GitHub error on one connector must not stop the rest from being reported.
    """
    failures = []
    for row in report["connectors"]:
        if not isinstance(row, dict) or not isinstance(row.get("key"), str):
            continue
        if not _KEY.fullmatch(row["key"]):
            continue
        try:
            _sync_one(row, github, close_recovered=close_recovered)
        except (RuntimeError, json.JSONDecodeError) as exc:
            failures.append(f"{row['key']}: {exc}")
    return failures


def _sync_one(row: dict, github, *, close_recovered: bool) -> None:
    status = row.get("status")
    if status == "not_checked":
        return
    title = f"Connector health: {row['key']} failing"
    matches = github.find(title)
    open_issue = _preferred(matches, "open")
    if status == "fail":
        last = _known_date(row.get("last_good"))
        last = (
            last or _last_good(open_issue) or _last_good(_preferred(matches, "closed"))
        )
        body = render_failure(row, last)
        if open_issue:
            github.comment(int(open_issue["number"]), body)
        elif (closed := _preferred(matches, "closed")) is not None:
            github.reopen(int(closed["number"]), body)
        else:
            github.create(title, body, LABELS)
    elif status == "ok" and close_recovered and open_issue:
        github.close(int(open_issue["number"]), render_recovered(row))


def render_failure(row: dict, last_good: str | None) -> str:
    code = row.get("status_code")
    lines = [
        f"Connector `{row['key']}` is failing.",
        "",
        f"Status code: {code if isinstance(code, int) else 'unknown'}",
        f"Error class: {_public_error(row)}",
        f"Last good: {last_good or 'unknown'}",
    ]
    changes = clean_diff(row.get("schema_diff"))
    if changes:
        lines.extend(["", "Schema diff:"])
        for item in changes:
            where = _where(item)
            if item["change"] == "added":
                lines.append(f"- field added: {where}")
            elif item["change"] == "removed":
                lines.append(f"- field removed: {where}")
            else:
                lines.append(
                    f"- type changed: {where} from {item['from']} to {item['to']}"
                )
    return "\n".join(lines) + "\n"


def render_recovered(row: dict) -> str:
    code = row.get("status_code")
    last = _known_date(row.get("last_good")) or "unknown"
    shown = code if isinstance(code, int) else "unknown"
    return (
        f"Connector `{row['key']}` has recovered.\n\n"
        f"Status code: {shown}\n"
        f"Last good: {last}\n"
    )


def clean_diff(items: object) -> list[dict]:
    if not isinstance(items, list):
        return []
    cleaned = []
    for item in items:
        if not isinstance(item, dict):
            continue
        change = item.get("change")
        field = item.get("field")
        if change not in {"added", "removed", "type_changed"} or not isinstance(
            field, str
        ):
            continue
        if not _FIELD.fullmatch(field):
            continue
        entry = {"change": change, "field": field}
        schema = item.get("schema")
        if isinstance(schema, str) and _FIELD.fullmatch(schema):
            entry["schema"] = schema
        if change == "type_changed":
            origin = _safe_type(item.get("from"))
            target = _safe_type(item.get("to"))
            if origin is None or target is None:
                continue
            entry["from"] = origin
            entry["to"] = target
        if any(key in _HIDDEN for key in item):
            continue
        cleaned.append(entry)
    return cleaned


def _public_error(row: dict) -> str:
    value = row.get("error_class")
    if isinstance(value, str) and _ERROR.fullmatch(value):
        return value
    return "unknown"


def _where(item: dict) -> str:
    field = item["field"]
    schema = item.get("schema")
    if schema:
        return f"{field} ({schema})"
    return field


def _safe_type(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    if value in _TYPES:
        return value
    parts = value.split("/")
    if parts and all(part in _TYPES for part in parts):
        return value
    return None


def _known_date(value: object) -> str | None:
    if isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return value
    return None


def _last_good(issue: dict | None) -> str | None:
    if not issue:
        return None
    match = _LAST_GOOD.search(str(issue.get("body") or ""))
    return match.group(1) if match else None


def _preferred(issues: list[dict], state: str) -> dict | None:
    chosen = [item for item in issues if item.get("state") == state]
    if not chosen:
        return None
    return min(chosen, key=lambda item: int(item["number"]))


class GhCli:
    """GitHub issues via the gh CLI. Tests pass a fake client instead."""

    def find(self, title: str) -> list[dict]:
        found = []
        for state in ("open", "closed"):
            raw = self._run(
                [
                    "issue",
                    "list",
                    "--state",
                    state,
                    "--limit",
                    "50",
                    "--json",
                    "number,title,state,body",
                    "--search",
                    f'"{title}" in:title',
                ]
            )
            rows = json.loads(raw or "[]")
            if not isinstance(rows, list):
                continue
            for row in rows:
                if isinstance(row, dict) and row.get("title") == title:
                    found.append(row)
        return found

    def create(self, title: str, body: str, labels: list[str]) -> int:
        args = ["issue", "create", "--title", title, "--body", body]
        for label in labels:
            args.extend(["--label", label])
        match = re.search(r"/issues/(\d+)$", self._run(args).strip())
        if not match:
            raise RuntimeError("gh issue create did not return an issue number")
        return int(match.group(1))

    def comment(self, number: int, body: str) -> None:
        self._run(["issue", "comment", str(number), "--body", body])
        self._run(["issue", "edit", str(number), "--body", body])

    def close(self, number: int, body: str) -> None:
        self._run(["issue", "edit", str(number), "--body", body])
        self._run(
            ["issue", "close", str(number), "--reason", "completed", "--comment", body]
        )

    def reopen(self, number: int, body: str) -> None:
        self._run(["issue", "reopen", str(number)])
        self._run(["issue", "comment", str(number), "--body", body])
        self._run(["issue", "edit", str(number), "--body", body])

    def _run(self, args: list[str]) -> str:
        proc = subprocess.run(
            ["gh", *args], capture_output=True, text=True, check=False
        )
        if proc.returncode != 0:
            message = proc.stderr.strip() or "gh failed"
            raise RuntimeError(message)
        return proc.stdout


if __name__ == "__main__":
    raise SystemExit(main())
