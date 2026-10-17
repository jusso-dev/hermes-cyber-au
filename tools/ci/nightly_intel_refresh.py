"""Refresh public threat intel snapshots and refuse paths outside the data directories.

Calls ``cyberau-mcp refresh`` and ``cyberau-mcp store snapshot --public``.
Keyed sources are included only when their secret is set. If either command
is not part of the shared library yet, say so, and still refuse paths outside
the data directories.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from cyberau_common.secrets import redact

ROOT = Path(__file__).resolve().parents[2]

PUBLIC_SOURCES = "asd,kev,epss,auscert,attack,feodo"
OPTIONAL_SOURCES = "nvd,abusech,otx,radar"

KEYED_SECRETS = {
    "nvd": "NVD_API_KEY",
    "abusech": "ABUSECH_AUTH_KEY",
    "otx": "OTX_API_KEY",
    "radar": "CLOUDFLARE_RADAR_API_TOKEN",
}

ABSENT_MARKER = "is not part of the shared library yet"
REFRESH_ABSENT = f"cyberau-mcp refresh {ABSENT_MARKER}."
STORE_ABSENT = f"cyberau-mcp store snapshot {ABSENT_MARKER}."
REFUSAL_PREFIX = "Refusing paths outside the data directories:"

STORE_ARGS = ["store", "snapshot", "--public"]

_EXACT_PATHS = frozenset({"PR_BODY.md", "feeds", "intel/snapshots"})
_PREFIXES = ("feeds/", "intel/snapshots/")
_MCP_DATA = re.compile(r"mcp/[a-z0-9-]+/data(?:/.*)?")
_SKILL_REF = re.compile(r"skills/[a-z0-9-]+/references(?:/.*)?")


@dataclass(frozen=True)
class CommandResult:
    code: int
    stdout: str
    stderr: str


def split_csv(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def keyed_sources(requested: Sequence[str], env: Mapping[str, str]) -> list[str]:
    """Return keyed sources whose secret is set to a non-blank value."""
    selected: list[str] = []
    for name in requested:
        variable = KEYED_SECRETS.get(name)
        if variable is None:
            raise ValueError(f"Unknown keyed source: {name}. It was not refreshed.")
        if env.get(variable, "").strip():
            selected.append(name)
    return selected


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
        if "R" in status or "C" in status:
            if index >= len(parts):
                break
            path = parts[index]
            index += 1
        if path:
            paths.append(path)
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
    """True when this checkout has no implementation for the command."""
    text = f"{result.stdout}\n{result.stderr}"
    if ABSENT_MARKER in text:
        return True
    return result.code == 2 and "unrecognized arguments" in text


def scrub(text: str, env: Mapping[str, str]) -> str:
    cleaned = redact(text)
    for variable in KEYED_SECRETS.values():
        value = env.get(variable, "")
        if len(value) >= 8 and value in cleaned:
            cleaned = cleaned.replace(value, "[REDACTED]")
    return cleaned


def refresh_args(
    sources: str,
    optional: Sequence[str],
    outputs: Mapping[str, str] | None,
) -> list[str]:
    args = ["refresh", "--sources", sources]
    if optional:
        args.extend(["--optional-sources", ",".join(optional)])
    if outputs is not None:
        args.extend(
            [
                "--snapshot-dir",
                outputs["snapshot_dir"],
                "--catalogue",
                outputs["catalogue"],
                "--summary",
                outputs["summary"],
            ]
        )
    return args


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
    optional_sources: str,
    snapshot_dir: str,
    catalogue: str,
    summary: str,
    env: Mapping[str, str] | None = None,
    runner: Callable[[list[str]], CommandResult] | None = None,
    changes: Callable[[], list[str]] | None = None,
) -> int:
    current: Mapping[str, str] = os.environ if env is None else env
    call = runner or (lambda args: run_cyberau(args, current))
    list_changes = changes or (lambda: git_changes(ROOT))

    try:
        optional = keyed_sources(split_csv(optional_sources), current)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        set_output("open_pr", "false")
        return 1

    outputs = {
        "snapshot_dir": snapshot_dir,
        "catalogue": catalogue,
        "summary": summary,
    }
    bad_outputs = outside_data_dirs(outputs.values())
    refresh_result = call(refresh_args(sources, optional, None if bad_outputs else outputs))
    store_result = call(list(STORE_ARGS))

    exit_code = 0
    for label, result in (
        (REFRESH_ABSENT, refresh_result),
        (STORE_ABSENT, store_result),
    ):
        if is_absent(result):
            print(label)
            continue
        if result.code != 0:
            detail = scrub(result.stderr or result.stdout, current).strip()
            if detail:
                print(detail, file=sys.stderr)
            exit_code = result.code

    try:
        changed = list_changes()
    except RuntimeError as exc:
        print(scrub(str(exc), current), file=sys.stderr)
        set_output("open_pr", "false")
        return 1

    bad = sorted(set(bad_outputs) | set(outside_data_dirs(changed)))
    if bad:
        print(f"{REFUSAL_PREFIX} {', '.join(bad)}", file=sys.stderr)
        set_output("open_pr", "false")
        return 1
    if exit_code != 0:
        set_output("open_pr", "false")
        return exit_code
    set_output("open_pr", "true" if changed else "false")
    return 0


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Refresh public threat intel snapshots and the feed catalogue."
    )
    parser.add_argument("--sources", default=PUBLIC_SOURCES)
    parser.add_argument("--optional-sources", default=OPTIONAL_SOURCES)
    parser.add_argument("--snapshot-dir", default="intel/snapshots")
    parser.add_argument("--catalogue", default="feeds/catalogue.yaml")
    parser.add_argument("--summary", default="PR_BODY.md")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    return execute(
        sources=args.sources,
        optional_sources=args.optional_sources,
        snapshot_dir=args.snapshot_dir,
        catalogue=args.catalogue,
        summary=args.summary,
    )


if __name__ == "__main__":
    raise SystemExit(main())
