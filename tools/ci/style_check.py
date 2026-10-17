"""House style check for Australian English.

Hard failures are an em dash, an emoji, or a banned private name. American
spellings in prose are printed as hints and do not fail the check.

Banned names are SHA-256 hashes in tools/ci/private_names.sha256 so the
plaintext stays out of this public repository. If CYBERAU_PRIVATE_NAMES is
set, those newline-separated names are hashed in memory and checked as well.
The workflow does not set that variable and does not carry a secret.

Run from the repository root:

    uv run --project mcp python tools/ci/style_check.py
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from pathlib import Path

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    "data",
    "fixtures",
}
_TEXT_SUFFIXES = {".md", ".py", ".yml", ".yaml", ".toml", ".txt", ".sh", ".json"}
_PROSE_SUFFIXES = {".md", ".txt", ".yml", ".yaml"}
_EM_DASH = "\u2014"
_EMOJI = re.compile(
    "[\u2600-\u27bf\U0001f1e6-\U0001f1ff\U0001f300-\U0001f6ff\U0001f900-\U0001faff]"
)
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+-]{2,}")
_WORD = re.compile(r"[A-Za-z][A-Za-z'.-]{1,}")
_URL = re.compile(r"https?://\S+")
_HINTS = {
    "analyze": "analyse",
    "analyzed": "analysed",
    "analyzing": "analysing",
    "behavior": "behaviour",
    "behavioral": "behavioural",
    "behaviors": "behaviours",
    "center": "centre",
    "centered": "centred",
    "centers": "centres",
    "defense": "defence",
    "favorite": "favourite",
    "favorites": "favourites",
    "flavor": "flavour",
    "gray": "grey",
    "honor": "honour",
    "honors": "honours",
    "labeled": "labelled",
    "labeling": "labelling",
    "modeling": "modelling",
    "neighbor": "neighbour",
    "offense": "offence",
    "organization": "organisation",
    "organizations": "organisations",
    "organize": "organise",
    "organized": "organised",
    "organizing": "organising",
}
_HINT_RE = re.compile(
    r"\b(" + "|".join(sorted(_HINTS, key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)
_MAX_BYTES = 1_000_000
_ENV_NAMES = "CYBERAU_PRIVATE_NAMES"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check hermes-cyber-au house style.")
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    errors, hints = check(args.root.resolve(), extra_names=_names_from_env())
    for hint in hints:
        print(hint)
    for error in errors:
        print(error)
    return 1 if errors else 0


def check(
    root: Path,
    *,
    names_file: Path | None = None,
    extra_names: list[str] | tuple[str, ...] = (),
) -> tuple[list[str], list[str]]:
    """Return ``(errors, hints)``. Hints are Australian spelling suggestions."""
    errors: list[str] = []
    hints: list[str] = []
    hashes, hash_errors = _load_hashes(root, names_file)
    errors.extend(hash_errors)
    for name in extra_names:
        cleaned = name.strip().lower()
        if cleaned:
            hashes.add(_digest(cleaned))

    for path in _iter_files(root):
        rel = _rel(root, path)
        try:
            size = path.stat().st_size
        except OSError as exc:
            errors.append(f"{rel}: {exc.strerror or 'unreadable'}")
            continue
        if size > _MAX_BYTES:
            errors.append(f"{rel}: file is too large to scan")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            errors.append(f"{rel}: file is not valid UTF-8")
            continue
        errors.extend(_character_errors(rel, text, hashes))
        if path.suffix.lower() in _PROSE_SUFFIXES:
            hints.extend(_spelling_hints(rel, text))
    return errors, hints


def _character_errors(rel: str, text: str, hashes: set[str]) -> list[str]:
    findings: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if _EM_DASH in line:
            findings.append(f"{rel}:{number}: em dash")
        if _EMOJI.search(line):
            findings.append(f"{rel}:{number}: emoji")
        if hashes and _line_has_banned_name(line, hashes):
            findings.append(f"{rel}:{number}: banned private name")
    return findings


def _line_has_banned_name(line: str, hashes: set[str]) -> bool:
    for candidate in _candidates(line):
        if _digest(candidate) in hashes:
            return True
    return False


def _candidates(line: str) -> set[str]:
    found: set[str] = set()
    stripped = line.strip().lower()
    if 3 <= len(stripped) <= 240:
        found.add(stripped)
    for token in _TOKEN.findall(line):
        found.add(token.lower())
    words = [match.group(0).lower() for match in _WORD.finditer(line)]
    for width in (2, 3):
        for index in range(len(words) - width + 1):
            found.add(" ".join(words[index : index + width]))
    return found


def _spelling_hints(rel: str, text: str) -> list[str]:
    findings: list[str] = []
    fenced = False
    markdown = rel.endswith(".md")
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.lstrip()
        if markdown and stripped.startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            continue
        url_spans = [match.span() for match in _URL.finditer(line)]
        for match in _HINT_RE.finditer(line):
            if any(
                start <= match.start() and match.end() <= end
                for start, end in url_spans
            ):
                continue
            # Keep capitalised product and agency names such as "Integration Center".
            american_raw = match.group(1)
            if american_raw != american_raw.lower():
                continue
            american = american_raw.lower()
            australian = _HINTS[american]
            findings.append(
                f"{rel}:{number}: hint: {american!r} is American spelling; "
                f"the Australian spelling is {australian!r}"
            )
    return findings


def _load_hashes(root: Path, names_file: Path | None) -> tuple[set[str], list[str]]:
    path = names_file
    if path is None:
        candidate = root / "tools" / "ci" / "private_names.sha256"
        fallback = Path(__file__).resolve().parent / "private_names.sha256"
        path = candidate if candidate.is_file() else fallback
    rel = path.as_posix()
    if not path.is_file():
        return set(), [f"{rel}: private name hash list is missing"]
    hashes: set[str] = set()
    errors: list[str] = []
    for number, raw in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not re.fullmatch(r"[0-9a-fA-F]{64}", line):
            errors.append(
                f"{path.name}:{number}: private name entry must be a SHA-256 hex digest"
            )
            continue
        hashes.add(line.lower())
    return hashes, errors


def _names_from_env() -> list[str]:
    raw = os.environ.get(_ENV_NAMES, "")
    return [line.strip() for line in raw.splitlines() if line.strip()]


def _iter_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            name
            for name in dirnames
            if name not in _SKIP_DIRS and not name.endswith(".egg-info")
        ]
        for name in filenames:
            path = Path(dirpath) / name
            if (
                path.suffix.lower() in _TEXT_SUFFIXES
                or path.name == "private_names.sha256"
            ):
                found.append(path)
    return sorted(found)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _rel(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


if __name__ == "__main__":
    sys.exit(main())
