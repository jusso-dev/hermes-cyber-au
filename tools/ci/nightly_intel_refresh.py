"""Check that the public threat intel feeds still refresh live, and record their status.

Calls ``cyberau-mcp refresh`` for the keyless public sources that have a refresh
adapter. Live intel is not committed to the repository: each install refreshes
into its own intel store, and a copy in git would only go stale. The run writes
per-source status to ``feeds/status.json`` (beside the feed catalogue) and asks
for a pull request only when a source's status changed, not for new timestamps.
A required source that fails makes the run fail.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from cyberau_common.secrets import distribution_env_names, is_plain_config_name, redact

ROOT = Path(__file__).resolve().parents[2]

# Every public source with a refresh adapter in cyberau_common.refresh.
PUBLIC_SOURCES = "asd,kev,epss,auscert,feodo"

ABSENT_MARKER = "is not part of the shared library yet"
REFRESH_ABSENT = f"cyberau-mcp refresh {ABSENT_MARKER}."
ROOT_USAGE = "usage: cyberau-mcp [-h]"
REFUSAL_PREFIX = "Refusing paths outside the data directories:"

_EXACT_PATHS = frozenset({"PR_BODY.md", "feeds"})
_PREFIXES = ("feeds/",)
_MCP_DATA = re.compile(r"mcp/[a-z0-9-]+/data(?:/.*)?")
_SKILL_REF = re.compile(r"skills/[a-z0-9-]+/references(?:/.*)?")


@dataclass(frozen=True)
class CommandResult:
    code: int
    stdout: str
    stderr: str


def split_csv(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def repo_relative(path: str) -> str | None:
    """Return a repo-relative path, or None when it escapes the repository."""
    text = path.strip().replace("\\", "/")
    if not text or "\x00" in text or text.startswith("/") or (len(text) > 1 and text[1] == ":"):
        return None
    parts: list[str] = []
    for part in text.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            return None
        parts.append(part)
    if not parts:
        return None
    return "/".join(parts)


def allowed_data_path(path: str) -> bool:
    rel = repo_relative(path)
    if rel is None:
        return False
    if rel in _EXACT_PATHS or rel.startswith(_PREFIXES):
        return True
    return _MCP_DATA.fullmatch(rel) is not None or _SKILL_REF.fullmatch(rel) is not None


def outside_data_dirs(paths: Sequence[str]) -> list[str]:
    bad = [path.strip() or path for path in paths if not allowed_data_path(path)]
    return sorted(set(bad))


def parse_porcelain_z(data: str) -> list[str]:
    parts = data.split("\0")
    if parts and parts[-1] == "":
        parts.pop()
    paths: list[str] = []
    index = 0
    while index < len(parts):
        entry = parts[index]
        index += 1
        if len(entry) < 4:
            continue
        status = entry[:2]
        path = entry[3:]
        if path:
            paths.append(path)
        if "R" in status or "C" in status:
            if index >= len(parts):
                break
            paths.append(parts[index])
            index += 1
    return paths


def git_changes(root: Path) -> list[str]:
    proc = subprocess.run(
        ["git", "status", "--porcelain", "-z", "--untracked-files=all"],
        cwd=root,
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        message = redact(proc.stderr.strip()) or "git status failed"
        raise RuntimeError(message)
    return parse_porcelain_z(proc.stdout)


def is_absent(result: CommandResult) -> bool:
    """True only when the shared library has no such command (exit 2)."""
    if result.code != 2:
        return False
    if ABSENT_MARKER in result.stderr:
        return True
    return "unrecognized arguments" in result.stderr and ROOT_USAGE in result.stderr


def status_signature(path: Path) -> dict[str, str]:
    """Each source's ok/fail status, without timestamps or counts."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    sources = payload.get("sources") if isinstance(payload, dict) else None
    if not isinstance(sources, dict):
        return {}
    return {
        str(name): str(entry.get("status") or "")
        for name, entry in sources.items()
        if isinstance(entry, dict)
    }


def scrub(text: str, env: Mapping[str, str]) -> str:
    cleaned = redact(text)
    names = set(distribution_env_names()) | {
        name for name in env if re.search(r"KEY|TOKEN|SECRET|PASSWORD", name, re.IGNORECASE)
    }
    for name in names:
        value = env.get(name, "")
        if not is_plain_config_name(name) and len(value) >= 8:
            cleaned = cleaned.replace(value, "[REDACTED]")
    return cleaned


def scrub_file(path: Path, env: Mapping[str, str]) -> None:
    if path.is_file():
        text = path.read_text(encoding="utf-8", errors="replace")
        cleaned = scrub(text, env)
        if cleaned != text:
            path.write_text(cleaned, encoding="utf-8")


def refresh_args(sources: str, catalogue: str, summary: str) -> list[str]:
    return ["refresh", "--sources", sources, "--catalogue", catalogue, "--summary", summary]


def run_cyberau(args: Sequence[str], env: Mapping[str, str]) -> CommandResult:
    exe = shutil.which("cyberau-mcp")
    if exe is None:
        return CommandResult(2, "", f"cyberau-mcp {ABSENT_MARKER}")
    proc = subprocess.run(
        [exe, *args],
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
        env={key: str(value) for key, value in env.items()},
    )
    return CommandResult(proc.returncode, proc.stdout, proc.stderr)


def set_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path or "\n" in value:
        return
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")


def execute(
    *,
    sources: str,
    catalogue: str,
    summary: str,
    env: Mapping[str, str] | None = None,
    runner: Callable[[list[str]], CommandResult] | None = None,
    changes: Callable[[], list[str]] | None = None,
    root: Path = ROOT,
) -> int:
    current: Mapping[str, str] = os.environ if env is None else env
    call = runner or (lambda args: run_cyberau(args, current))
    list_changes = changes or (lambda: git_changes(root))

    bad_outputs = outside_data_dirs([catalogue, summary])
    if bad_outputs:
        print(f"{REFUSAL_PREFIX} {', '.join(bad_outputs)}", file=sys.stderr)
        set_output("open_pr", "false")
        return 1
    status_path = root / (repo_relative(catalogue) or "feeds/catalogue.yaml")
    status_path = status_path.parent / "status.json"
    before = status_signature(status_path)

    result = call(refresh_args(sources, catalogue, summary))
    if is_absent(result):
        print(f"::error title=Intel refresh not run::{REFRESH_ABSENT}")
        set_output("open_pr", "false")
        return 1
    if result.stdout.strip():
        print(scrub(result.stdout.strip(), current))
    if result.code != 0:
        detail = scrub(result.stderr or result.stdout, current).strip()
        if detail:
            print(detail, file=sys.stderr)

    scrub_file(root / summary, current)
    scrub_file(status_path, current)

    try:
        changed = list_changes()
    except RuntimeError as exc:
        print(scrub(str(exc), current), file=sys.stderr)
        set_output("open_pr", "false")
        return 1
    bad = outside_data_dirs(changed)
    if bad:
        print(f"{REFUSAL_PREFIX} {', '.join(bad)}", file=sys.stderr)
        set_output("open_pr", "false")
        return 1

    after = status_signature(status_path)
    status_changed = before != after
    if status_changed:
        print("Feed status changed. Asking for a pull request.")
    set_output("open_pr", "true" if status_changed else "false")
    # A failed source still records its new status in the pull request, then fails the run.
    return result.code


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check the public intel feeds refresh live and record their status."
    )
    parser.add_argument("--sources", default=PUBLIC_SOURCES)
    parser.add_argument("--catalogue", default="feeds/catalogue.yaml")
    parser.add_argument("--summary", default="PR_BODY.md")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    return execute(sources=args.sources, catalogue=args.catalogue, summary=args.summary)


if __name__ == "__main__":
    raise SystemExit(main())
