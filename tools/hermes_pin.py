#!/usr/bin/env python3
"""Read and update the pinned Hermes release.

tools/hermes_pin.txt is the single source. ``get`` prints that tag.
``set`` writes the same tag into:

- distribution.yaml ``hermes_requires`` (lower bound, without the leading v)
- docker/Dockerfile ``HERMES_VERSION``
- ``HERMES_IMAGE`` in ci/workflows/ci.yml and .github/workflows/ci.yml

A missing consumer is an error, and nothing is written until every consumer
can be updated. That keeps the pins from drifting apart.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN_REL = Path("tools/hermes_pin.txt")
DIST_REL = Path("distribution.yaml")
DOCKER_REL = Path("docker/Dockerfile")
CI_RELS = (
    Path("ci/workflows/ci.yml"),
    Path(".github/workflows/ci.yml"),
)

TAG_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
DIST_RE = re.compile(
    r"^(?P<prefix>[ \t]*hermes_requires:\s*)(?P<q>['\"])>=(?P<ver>[^'\"]+)(?P=q)"
    r"(?P<trail>[ \t]*)$",
    re.MULTILINE,
)
CI_RE = re.compile(
    r"^(?P<prefix>[ \t]*HERMES_IMAGE:\s*nousresearch/hermes-agent:)"
    r"(?P<tag>\S+)(?P<suffix>[ \t]*(?:#.*)?)$",
    re.MULTILINE,
)
DOCKER_RE = re.compile(
    r"^(?P<prefix>[ \t]*(?:ARG|ENV)[ \t]+HERMES_VERSION=)"
    r"(?P<tag>\S+)(?P<suffix>[ \t]*(?:#.*)?)$",
    re.MULTILINE,
)
_SECRET = re.compile(r"(?:ghp_|gho_|ghu_|ghs_|github_pat_)[A-Za-z0-9_]+")


class PinError(Exception):
    """The pin could not be read or written."""


def redact(text: str) -> str:
    return _SECRET.sub("[redacted]", text)


def _shown(tag: str) -> str:
    text = redact(tag.replace("\n", "\\n").replace("\r", "\\r"))
    if len(text) > 80:
        return text[:80] + "..."
    return text


def validate_tag(tag: str) -> str:
    if TAG_RE.fullmatch(tag):
        return tag
    raise PinError(f"Refusing tag {_shown(tag)!r}. Expected a release like v0.22.2.")


def floor_version(tag: str) -> str:
    validate_tag(tag)
    return tag[1:]


def _inside(root: Path, rel: Path) -> Path:
    base = root.resolve()
    path = (base / rel).resolve()
    if not path.is_relative_to(base):
        raise PinError(
            f"Refusing to touch a path outside the repository: {rel.as_posix()}"
        )
    return path


def _read(root: Path, rel: Path) -> str:
    path = _inside(root, rel)
    if not path.is_file():
        raise PinError(f"Missing {rel.as_posix()}")
    return path.read_text(encoding="utf-8")


def _replace_exact(text: str, pattern: re.Pattern[str], repl, rel: Path) -> str:
    new, count = pattern.subn(repl, text)
    if count != 1:
        raise PinError(
            f"{rel.as_posix()} needs exactly one Hermes pin assignment, found {count}"
        )
    return new


def read_pin(root: Path) -> str:
    text = _read(root, PIN_REL)
    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if len(lines) != 1:
        raise PinError("tools/hermes_pin.txt must contain one release tag")
    return validate_tag(lines[0])


def _render_pin(root: Path, tag: str) -> str:
    """Keep the leading comment block so the pin file still explains itself."""
    path = _inside(root, PIN_REL)
    comments: list[str] = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            if line.strip().startswith("#"):
                comments.append(line)
                continue
            break
    return "\n".join([*comments, tag]) + "\n"


def _plan(root: Path, tag: str) -> list[tuple[Path, str]]:
    version = floor_version(tag)
    planned: list[tuple[Path, str]] = [(PIN_REL, _render_pin(root, tag))]

    def dist_repl(match: re.Match[str]) -> str:
        return f"{match.group('prefix')}{match.group('q')}>={version}{match.group('q')}{match.group('trail')}"

    planned.append(
        (DIST_REL, _replace_exact(_read(root, DIST_REL), DIST_RE, dist_repl, DIST_REL))
    )

    def docker_repl(match: re.Match[str]) -> str:
        return f"{match.group('prefix')}{tag}{match.group('suffix') or ''}"

    planned.append(
        (
            DOCKER_REL,
            _replace_exact(_read(root, DOCKER_REL), DOCKER_RE, docker_repl, DOCKER_REL),
        )
    )

    ci_found = False
    for rel in CI_RELS:
        path = _inside(root, rel)
        if not path.is_file():
            continue
        ci_found = True

        def ci_repl(match: re.Match[str], release: str = tag) -> str:
            return f"{match.group('prefix')}{release}{match.group('suffix') or ''}"

        planned.append(
            (rel, _replace_exact(path.read_text(encoding="utf-8"), CI_RE, ci_repl, rel))
        )
    if not ci_found:
        looked = ", ".join(rel.as_posix() for rel in CI_RELS)
        raise PinError(f"Missing ci.yml. Looked for {looked}")
    return planned


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(text, encoding="utf-8", newline="\n")
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def set_pin(root: Path, tag: str) -> None:
    """Write ``tag`` to the pin file and every consumer. All writes happen, or none."""
    release = validate_tag(tag)
    planned = _plan(root, release)
    for rel, text in planned:
        _atomic_write(_inside(root, rel), text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read and update the pinned Hermes release."
    )
    parser.add_argument("--root", type=Path, default=ROOT)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("get", help="Print the pinned release tag")
    set_parser = sub.add_parser("set", help="Write a release tag through every pin")
    set_parser.add_argument("tag")
    args = parser.parse_args(argv)
    try:
        if args.command == "get":
            print(read_pin(args.root))
            return 0
        set_pin(args.root, args.tag)
    except PinError as exc:
        print(redact(str(exc)), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
