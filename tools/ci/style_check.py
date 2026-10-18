"""House style check for Australian English.

Hard failures are an em dash, an emoji, or a banned private name. American
spellings in prose are printed as hints and do not fail the check.

Banned names are SHA-256 hashes in tools/ci/private_names.sha256 so the
plaintext stays out of this public repository. If CYBERAU_PRIVATE_NAMES is
set, those newline-separated names are hashed in memory and checked as well.
Hash a name as lowercase words separated by single spaces; matching ignores
case and punctuation, so a hashed "acme" also catches "Acme." and "acme_corp".

The hashes are not secret. An unsalted SHA-256 of a short name can be
reversed with a word list, so treat the hash file as public. A masked
CYBERAU_PRIVATE_NAMES repository secret keeps names out of the repository
entirely.

When no banned names are configured the check cannot catch any, so it says
so on every run (as a GitHub Actions warning annotation in CI). Pass
--require-names, or set CYBERAU_REQUIRE_PRIVATE_NAMES=1, to fail instead.

Add a name without echoing it or writing the plaintext anywhere:

    uv run --project mcp python tools/ci/style_check.py --add-name

Run from the repository root:

    uv run --project mcp python tools/ci/style_check.py
"""

from __future__ import annotations

import argparse
import getpass
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
    "fixtures",
}
# Bundled upstream feed data under mcp/ is third-party text, not our prose.
_VENDORED_DIRS = {"data"}
_VENDORED_ROOT = "mcp"
_TEXT_SUFFIXES = {".md", ".py", ".yml", ".yaml", ".toml", ".txt", ".sh", ".json"}
_PROSE_SUFFIXES = {".md", ".txt", ".yml", ".yaml"}
# U+2014 plus the look-alike dashes U+2015, U+2E3A, U+2E3B and U+FE58.
_EM_DASH = re.compile("[\u2014\u2015\u2e3a\u2e3b\ufe58]")
_EMOJI = re.compile(
    "[\u231a\u231b\u23e9-\u23f3\u23f8-\u23fa\u25fd\u25fe"
    "\u2600-\u27bf\u2b1b\u2b1c\u2b50\u2b55\ufe0f"
    "\U0001f000-\U0001f6ff\U0001f900-\U0001faff]"
)
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+-]{2,}")
_WORD = re.compile(r"[A-Za-z][A-Za-z'.-]{1,}")
_ALNUM = re.compile(r"[a-z0-9]+")
_MAX_WORDS = 4
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
_ENV_REQUIRE = "CYBERAU_REQUIRE_PRIVATE_NAMES"
_NO_NAMES = (
    "private name check is not active: tools/ci/private_names.sha256 has no hashes "
    f"and {_ENV_NAMES} is unset. Add hashes with --add-name (see issue #156)."
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check hermes-cyber-au house style.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--add-name",
        action="store_true",
        help="read one name from the terminal or stdin and append its hash; never echoes it",
    )
    parser.add_argument(
        "--require-names",
        action="store_true",
        help=f"fail when no banned names are configured (or set {_ENV_REQUIRE}=1)",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if args.add_name:
        return _add_name_interactive(root)
    extra = _names_from_env()
    errors, hints = check(root, extra_names=extra)
    for hint in hints:
        print(hint)
    for error in errors:
        print(error)
    if not _active_hashes(root, extra):
        require = args.require_names or os.environ.get(_ENV_REQUIRE, "") == "1"
        if require:
            print(f"error: {_NO_NAMES}")
            return 1
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print(f"::warning title=Private name check inactive::{_NO_NAMES}")
        else:
            print(f"warning: {_NO_NAMES}", file=sys.stderr)
    return 1 if errors else 0


def normalise_name(name: str) -> str:
    """Lowercase words joined by single spaces, the form _candidates produces."""
    return " ".join(_ALNUM.findall(name.lower()))


def name_digest(name: str) -> str:
    cleaned = normalise_name(name)
    if not cleaned:
        raise ValueError("name has no letters or digits")
    if len(cleaned.split(" ")) > _MAX_WORDS:
        raise ValueError(f"name has more than {_MAX_WORDS} words and could never match")
    return _digest(cleaned)


def add_name(names_file: Path, name: str) -> bool:
    """Append the hash of ``name``. Returns False if it was already listed."""
    digest = name_digest(name)
    existing, _errors = _load_hashes(names_file.parent, names_file)
    if digest in existing:
        return False
    text = names_file.read_text(encoding="utf-8") if names_file.is_file() else ""
    if text and not text.endswith("\n"):
        text += "\n"
    names_file.write_text(text + digest + "\n", encoding="utf-8")
    return True


def _add_name_interactive(root: Path) -> int:
    names_file = root / "tools" / "ci" / "private_names.sha256"
    if sys.stdin.isatty():
        name = getpass.getpass("Name to ban (not echoed): ")
    else:
        name = sys.stdin.readline()
    try:
        added = add_name(names_file, name)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    rel = _rel(root, names_file)
    print(f"added a hash to {rel}" if added else f"that name is already in {rel}")
    return 0


def _active_hashes(root: Path, extra_names: list[str] | tuple[str, ...] = ()) -> bool:
    hashes, _errors = _load_hashes(root, None)
    return bool(hashes) or any(name.strip() for name in extra_names)


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
        if _EM_DASH.search(line):
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
    # Punctuation-insensitive runs, so "Acme." or "git.acme.internal" or
    # "acme_corp" still match a hashed "acme", and "Blue Falcon." a hashed
    # "blue falcon". Hash names as lowercase words separated by single spaces.
    parts = _ALNUM.findall(line.lower())
    for width in range(1, _MAX_WORDS + 1):
        for index in range(len(parts) - width + 1):
            found.add(" ".join(parts[index : index + width]))
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
            if any(start <= match.start() and match.end() <= end for start, end in url_spans):
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
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not re.fullmatch(r"[0-9a-fA-F]{64}", line):
            errors.append(f"{path.name}:{number}: private name entry must be a SHA-256 hex digest")
            continue
        hashes.add(line.lower())
    return hashes, errors


def _names_from_env() -> list[str]:
    raw = os.environ.get(_ENV_NAMES, "")
    return [line.strip() for line in raw.splitlines() if line.strip()]


def _iter_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        vendored = Path(dirpath).relative_to(root).parts[:1] == (_VENDORED_ROOT,)
        dirnames[:] = [
            name
            for name in dirnames
            if name not in _SKIP_DIRS
            and not name.endswith(".egg-info")
            and not (vendored and name in _VENDORED_DIRS)
        ]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() in _TEXT_SUFFIXES or path.name == "private_names.sha256":
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
