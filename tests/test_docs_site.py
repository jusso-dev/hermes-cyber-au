"""The docs site builds strictly: every page is in the nav and every link resolves.

This mirrors what `mkdocs build --strict` checks, without needing mkdocs or the
network, so it runs in the normal test job. The full build runs in
.github/workflows/docs.yml.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
LINK = re.compile(r"(?<!!)\]\(([^)\s]+)\)")
FENCE = re.compile(r"^\s*(```|~~~)")
SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:")


def _nav_paths(node) -> list[str]:
    found: list[str] = []
    if isinstance(node, str):
        found.append(node)
    elif isinstance(node, list):
        for item in node:
            found.extend(_nav_paths(item))
    elif isinstance(node, dict):
        for value in node.values():
            found.extend(_nav_paths(value))
    return found


def _config() -> dict:
    # mkdocs.yml has no custom tags, so safe_load is enough.
    return yaml.safe_load((ROOT / "mkdocs.yml").read_text(encoding="utf-8"))


def _pages() -> list[str]:
    return sorted(path.relative_to(DOCS).as_posix() for path in DOCS.rglob("*.md"))


def _links(text: str):
    fenced = False
    for number, line in enumerate(text.splitlines(), start=1):
        if FENCE.match(line):
            fenced = not fenced
            continue
        if fenced:
            continue
        stripped = re.sub(r"`[^`]*`", "", line)
        for match in LINK.finditer(stripped):
            yield number, match.group(1)


def test_strict_validation_is_on():
    config = _config()
    assert config["docs_dir"] == "docs"
    validation = config.get("validation") or {}
    for key in ("omitted_files", "absolute_links", "unrecognized_links", "anchors"):
        assert validation.get(key) == "warn", key


def test_every_page_is_in_the_nav_and_every_nav_entry_exists():
    nav = _nav_paths(_config()["nav"])
    missing_files = sorted(path for path in nav if not (DOCS / path).is_file())
    assert missing_files == [], f"nav entries with no file: {missing_files}"
    not_in_nav = sorted(set(_pages()) - set(nav))
    assert not_in_nav == [], (
        f"pages missing from the mkdocs.yml nav: {not_in_nav}. Add them by hand, or "
        "run tools/build_connector_docs.py for docs/connectors/."
    )


def test_relative_links_stay_inside_docs_and_resolve():
    problems: list[str] = []
    for rel in _pages():
        text = (DOCS / rel).read_text(encoding="utf-8")
        for number, target in _links(text):
            if SCHEME.match(target) or target.startswith(("#", "/")):
                continue
            path = target.split("#", 1)[0]
            if not path:
                continue
            inside = os.path.normpath(os.path.join(os.path.dirname(rel), path))
            if inside.startswith(".."):
                problems.append(
                    f"docs/{rel}:{number}: {target} leaves docs/. Use an absolute GitHub URL."
                )
            elif not (DOCS / inside).exists():
                problems.append(f"docs/{rel}:{number}: {target} does not exist")
    assert problems == [], "\n".join(problems)


def test_connectors_index_is_reachable():
    assert (DOCS / "connectors" / "index.md").is_file()
    nav = _nav_paths(_config()["nav"])
    for page in (DOCS / "connectors").glob("*.md"):
        assert f"connectors/{page.name}" in nav, page.name
