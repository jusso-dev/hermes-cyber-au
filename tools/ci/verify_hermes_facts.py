#!/usr/bin/env python3
"""Re-check every fact in docs/research/hermes-structure.md against a Hermes tag.

Each table row becomes one or more checks, taken from its Source cell:

- a path (file exists, or a directory when the path ends with /)
- a bare identifier, or one attached to a Python file (symbol exists)
- a double-quoted phrase attached to a file (string present)

Upstream file bodies stay out of the report. They are untrusted input and are
only searched, never copied.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FACTS = ROOT / "docs" / "research" / "hermes-structure.md"
REPO_URL = "https://github.com/NousResearch/hermes-agent.git"
TAG_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
REF_RE = re.compile(r"`([^`]+)`(?:\s*\(([^)]*)\))?")
_SECRET = re.compile(r"(?:ghp_|gho_|ghu_|ghs_|github_pat_)[A-Za-z0-9_]+")
_SECRET_ENV = ("TOKEN", "SECRET", "PASSWORD", "PASSWD")

LABELS = {
    "file": "file exists",
    "symbol": "symbol exists",
    "string": "string present",
}


class VerifyError(Exception):
    """The notes could not be checked."""


def redact(text: str) -> str:
    return _SECRET.sub("[redacted]", text)


def _shown(value: str) -> str:
    text = redact(value.replace("\n", "\\n").replace("\r", "\\r"))
    if len(text) > 120:
        return text[:120] + "..."
    return text


def validate_tag(tag: str) -> str:
    if TAG_RE.fullmatch(tag):
        return tag
    raise VerifyError(f"Refusing tag {_shown(tag)!r}. Expected a release like v0.22.2.")


@dataclass(frozen=True)
class Check:
    kind: str
    target: str
    bound: str | None = None


@dataclass(frozen=True)
class Fact:
    number: int
    summary: str
    checks: tuple[Check, ...]


@dataclass(frozen=True)
class Outcome:
    ok: bool
    fact: Fact
    check: Check
    detail: str


def _split_row(line: str) -> list[str]:
    cells: list[str] = []
    current: list[str] = []
    in_code = False
    for char in line:
        if char == "`":
            in_code = not in_code
            current.append(char)
        elif char == "|" and not in_code:
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    cells.append("".join(current).strip())
    if cells and cells[0] == "":
        cells = cells[1:]
    if cells and cells[-1] == "":
        cells = cells[:-1]
    return cells


def _split_paren(text: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    in_code = False
    for char in text:
        if char == "`":
            in_code = not in_code
            current.append(char)
        elif char == "," and not in_code:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _is_path(token: str) -> bool:
    return (
        "/" in token
        or token == "Dockerfile"
        or token.endswith((".md", ".py", ".yaml", ".yml", ".sh", ".txt"))
    )


def _safe_relative(ref: str) -> None:
    if ref.startswith(("/", "\\")) or "\\" in ref:
        raise VerifyError(f"Refusing absolute citation {_shown(ref)!r}")
    if ".." in Path(ref).parts:
        raise VerifyError(f"Refusing parent citation {_shown(ref)!r}")


def _checks_from_paren(bound: str, paren: str) -> list[Check]:
    checks: list[Check] = []
    for part in _split_paren(paren):
        item = part.strip()
        if not item:
            continue
        symbol = re.fullmatch(r"`([^`]+)`", item)
        quoted = re.fullmatch(r'"([^"]+)"', item)
        if symbol:
            checks.append(Check("symbol", symbol.group(1), bound))
        elif quoted:
            checks.append(Check("string", quoted.group(1), bound))
        else:
            raise VerifyError(f"Unrecognised citation {_shown(item)!r} on {_shown(bound)}")
    return checks


def checks_from_source(source: str) -> tuple[Check, ...]:
    checks: list[Check] = []
    for match in REF_RE.finditer(source):
        token = match.group(1).strip()
        paren = match.group(2)
        _safe_relative(token)
        if _is_path(token):
            checks.append(Check("file", token))
            if paren:
                checks.extend(_checks_from_paren(token, paren))
        else:
            if paren:
                raise VerifyError(f"Symbol {_shown(token)!r} cannot carry its own citation")
            checks.append(Check("symbol", token))
    return tuple(checks)


def summarise(fact: str) -> str:
    text = fact.replace("\\|", "|")
    text = text.replace("`", "")
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > 160:
        return text[:157] + "..."
    return text


def parse_facts(markdown: str) -> list[Fact]:
    facts: list[Fact] = []
    for line in markdown.splitlines():
        if not line.startswith("|"):
            continue
        if re.match(r"^\|\s*-+", line):
            continue
        cells = _split_row(line)
        if len(cells) < 2:
            continue
        if cells[0] == "Fact" and cells[1] == "Source":
            continue
        checks = checks_from_source(cells[1])
        if not checks:
            raise VerifyError(f"Fact has no checks: {_shown(cells[0])}")
        facts.append(Fact(len(facts) + 1, summarise(cells[0]), checks))
    if not facts:
        raise VerifyError("No facts found in the Hermes structure notes")
    return facts


class Tree:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        if not self.root.is_dir():
            raise VerifyError(f"Checkout does not exist: {self.root}")
        self.files = self._index()

    def _index(self) -> set[str]:
        found: set[str] = set()
        for path in self.root.rglob("*"):
            if ".git" in path.parts:
                continue
            if not path.is_file():
                continue
            resolved = path.resolve()
            if not resolved.is_relative_to(self.root):
                continue
            found.add(path.relative_to(self.root).as_posix())
        return found

    def _rank(self, path: str) -> tuple[int, int, str]:
        if path.startswith("website/docs/"):
            tier = 0
        elif "/i18n/" in path:
            tier = 2
        else:
            tier = 1
        return (tier, len(path), path)

    def resolve(self, ref: str) -> str:
        _safe_relative(ref)
        if ref.endswith("/"):
            directory = (self.root / ref).resolve()
            if not directory.is_relative_to(self.root) or not directory.is_dir():
                raise VerifyError(f"Missing directory {ref}")
            return ref
        if ref in self.files:
            return ref
        suffix = "/" + ref
        hits = [path for path in self.files if path.endswith(suffix)]
        if not hits:
            raise VerifyError(f"Missing file {ref}")
        hits.sort(key=self._rank)
        return hits[0]

    def read(self, rel: str) -> str:
        _safe_relative(rel)
        path = (self.root / rel).resolve()
        if not path.is_relative_to(self.root) or not path.is_file():
            raise VerifyError(f"Missing file {rel}")
        return path.read_text(encoding="utf-8", errors="replace")


def _contains_symbol(text: str, name: str) -> bool:
    return re.search(r"\b" + re.escape(name) + r"\b", text) is not None


def _run_check(tree: Tree, fact: Fact, check: Check) -> Outcome:
    try:
        if check.kind == "file":
            return Outcome(True, fact, check, tree.resolve(check.target))
        if check.kind == "symbol" and check.bound:
            resolved = tree.resolve(check.bound)
            if _contains_symbol(tree.read(resolved), check.target):
                return Outcome(True, fact, check, resolved)
            return Outcome(False, fact, check, resolved)
        if check.kind == "symbol":
            for rel in sorted(path for path in tree.files if path.endswith(".py")):
                if _contains_symbol(tree.read(rel), check.target):
                    return Outcome(True, fact, check, rel)
            return Outcome(False, fact, check, "not found in any Python file")
        if check.kind == "string":
            if not check.bound:
                return Outcome(False, fact, check, "string has no file")
            resolved = tree.resolve(check.bound)
            if check.target in tree.read(resolved):
                return Outcome(True, fact, check, resolved)
            return Outcome(False, fact, check, resolved)
    except VerifyError as exc:
        return Outcome(False, fact, check, str(exc))
    return Outcome(False, fact, check, "unknown check")


def run_checks(tree: Tree, facts: list[Fact]) -> list[Outcome]:
    outcomes: list[Outcome] = []
    for fact in facts:
        for check in fact.checks:
            outcomes.append(_run_check(tree, fact, check))
    return outcomes


def _clone_env() -> dict[str, str]:
    """Public clone. Drop credential-shaped variables so they cannot reach git or the log."""
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    for name in list(env):
        upper = name.upper()
        if any(piece in upper for piece in _SECRET_ENV) or upper.endswith("_KEY"):
            env.pop(name, None)
    return env


def checkout_tag(tag: str) -> Path:
    release = validate_tag(tag)
    dest = Path(tempfile.mkdtemp(prefix="hermes-facts-"))
    proc = subprocess.run(
        [
            "git",
            "clone",
            "--quiet",
            "--depth",
            "1",
            "--branch",
            release,
            REPO_URL,
            str(dest),
        ],
        capture_output=True,
        text=True,
        env=_clone_env(),
        check=False,
    )
    if proc.returncode != 0:
        shutil.rmtree(dest, ignore_errors=True)
        detail = redact((proc.stderr or proc.stdout or "git clone failed").strip())
        last = detail.splitlines()[-1] if detail else "git clone failed"
        raise VerifyError(f"Could not fetch Hermes tag {release}: {last[:300]}")
    return dest


def render_report(label: str, facts_path: Path, outcomes: list[Outcome]) -> str:
    passed = sum(1 for item in outcomes if item.ok)
    failed = len(outcomes) - passed
    try:
        shown_facts = facts_path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        shown_facts = facts_path.name
    lines = [
        "# Hermes fact check",
        "",
        f"Notes: {shown_facts}",
        f"Target: {label}",
        f"Facts: {len({item.fact.number for item in outcomes})}",
        f"Checks: {passed} passed, {failed} failed.",
        "",
    ]
    for item in outcomes:
        label_text = LABELS.get(item.check.kind, item.check.kind)
        if item.check.kind == "string":
            subject = f'"{item.check.target}"'
        else:
            subject = f"`{item.check.target}`"
        where = item.detail
        if item.ok and item.check.kind == "file" and where == item.check.target:
            location = ""
        elif item.ok and item.check.kind == "file":
            location = f" at `{where}`"
        elif item.ok:
            location = f" in `{where}`"
        elif where.startswith(("Missing", "Refusing")) or where == "not found in any Python file":
            location = f" {where}"
        else:
            location = f" not in `{where}`"
        if item.ok:
            lines.append(f"- pass fact {item.fact.number} {label_text}: {subject}{location}")
        else:
            lines.append(
                f"- fail fact {item.fact.number} ({item.fact.summary}) "
                f"{label_text}: {subject}{location}"
            )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Re-check Hermes structure notes against a tag.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--tag", help="Hermes release tag to clone, for example v0.22.2")
    source.add_argument("--checkout", type=Path, help="Existing Hermes checkout, for tests")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--facts", type=Path, default=DEFAULT_FACTS)
    args = parser.parse_args(argv)

    owned: Path | None = None
    try:
        if not args.facts.is_file():
            raise VerifyError(f"Missing facts file: {args.facts}")
        facts = parse_facts(args.facts.read_text(encoding="utf-8"))
        if args.tag:
            owned = checkout_tag(args.tag)
            tree = Tree(owned)
            label = args.tag
        else:
            tree = Tree(args.checkout)
            label = str(args.checkout)
        outcomes = run_checks(tree, facts)
        report = render_report(label, args.facts, outcomes)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report, encoding="utf-8", newline="\n")
    except VerifyError as exc:
        print(redact(str(exc)), file=sys.stderr)
        return 1
    finally:
        if owned is not None:
            shutil.rmtree(owned, ignore_errors=True)

    failed = [item for item in outcomes if not item.ok]
    print(f"{len(outcomes) - len(failed)} passed, {len(failed)} failed")
    if failed:
        for item in failed:
            print(
                f"fail fact {item.fact.number} {LABELS.get(item.check.kind, item.check.kind)}: "
                f"{_shown(item.check.target)}",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
