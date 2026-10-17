"""Regenerate local skill data. No network and no live pages."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

PARSER_CHECK_ABSENT = "parser-check is absent: not part of the shared library yet"

# Ticket paths first. This checkout stores ISM catalogues under mcp/asd-ism/data.
SOURCES: dict[str, tuple[str, tuple[str, ...]]] = {
    "ism": ("ISM", ("mcp/ism/data", "mcp/asd-ism/data")),
    "e8": ("Essential Eight", ("mcp/e8/data",)),
    "aureg": ("AU reporting obligations", ("mcp/aureg/data",)),
    "attack": ("ATT&CK", ("mcp/attack/data",)),
    "sigma": ("Sigma", ("mcp/sigma/data",)),
}

SKIP_MESSAGES = {
    "ism": "ISM data directory is absent. Skipping regen ism.",
    "e8": "Essential Eight data directory is absent. Skipping regen e8.",
    "aureg": "AU reporting obligations data directory is absent. Skipping regen aureg.",
    "attack": "ATT&CK data directory is absent. Skipping regen attack.",
    "sigma": "Sigma data directory is absent. Skipping regen sigma.",
}

SKILL_DIRECTORIES = {
    "ism": "ism-control-lookup",
    "e8": "essentials-assessment",
    "attack": "threat-hunting",
    "sigma": "threat-hunting",
}

_SKIP_FILES = {"regen.json", ".DS_Store"}


def regen_main(argv: list[str], root: Path | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyberau-mcp regen")
    parser.add_argument("source")
    parser.add_argument("--keep", type=int, default=2)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    if args.keep < 1:
        print("keep must be at least 1", file=sys.stderr)
        return 2
    if args.source not in SOURCES:
        print(f"regen does not know {args.source}.", file=sys.stderr)
        return 2
    base = Path.cwd() if root is None else root
    try:
        return regenerate(base, args.source, keep=args.keep, force=args.force)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1


def parser_check_main(argv: list[str]) -> int:
    """The advisory parsers are not in this checkout. Say so and do not fetch pages."""
    parser = argparse.ArgumentParser(prog="cyberau-mcp parser-check")
    parser.add_argument("--sources", default="")
    parser.add_argument("--json", dest="json_path", default="")
    args = parser.parse_args(argv)
    print(PARSER_CHECK_ABSENT, file=sys.stderr)
    if args.json_path:
        payload = {
            "absent": True,
            "detail": PARSER_CHECK_ABSENT,
            "results": [],
            "sources": [part for part in args.sources.split(",") if part],
        }
        Path(args.json_path).write_text(_dumps(payload), encoding="utf-8")
    return 2


def regenerate(root: Path, source: str, *, keep: int = 2, force: bool = False) -> int:
    label, _candidates = SOURCES[source]
    directory = locate(root, source)
    if directory is None:
        print(SKIP_MESSAGES[source])
        return 0
    relative = _relative(root, directory)
    if source == "ism":
        payload, removals = _ism_payload(root, directory, keep)
        for extra in removals:
            if not _within(directory, extra):
                raise ValueError(f"refusing to remove {extra.name}")
        if payload is None:
            print(f"{label} data directory has no catalogues.", file=sys.stderr)
            return 1
        for extra in removals:
            shutil.rmtree(extra)
        kept = ", ".join(payload["kept"])
        written = _write_manifest(directory, payload, force=force)
        if written or removals:
            print(f"Regenerated {label} data in {relative} (kept {kept}).")
        else:
            print(f"{label} data is unchanged.")
        return 0
    payload = _file_payload(root, source, directory)
    written = _write_manifest(directory, payload, force=force)
    if written:
        print(f"Regenerated {label} data in {relative}.")
    else:
        print(f"{label} data is unchanged.")
    return 0


def locate(root: Path, source: str) -> Path | None:
    _label, candidates = SOURCES[source]
    for relative in candidates:
        path = root / relative
        if path.is_dir():
            return path
    return None


def render_report(root: Path) -> str:
    lines = [
        "## Skill data regeneration",
        "",
        "Regenerated local data where a directory was present. Live pages were not fetched.",
        "",
    ]
    for source, (label, _candidates) in SOURCES.items():
        directory = locate(root, source)
        if directory is None:
            lines.append(f"- {SKIP_MESSAGES[source]}")
            continue
        lines.append(f"- {label}: using {_relative(root, directory)}")
        skill = SKILL_DIRECTORIES.get(source)
        if skill is None:
            continue
        skill_dir = root / "skills" / skill
        if not skill_dir.is_dir():
            lines.append(f"- Skill directory skills/{skill} is absent. Not writing references.")
            continue
        reference = _write_reference(source, directory, skill_dir)
        lines.append(f"- Skill references: wrote {_relative(root, reference)}")
    lines.extend(["", PARSER_CHECK_ABSENT, ""])
    return "\n".join(lines)


def count_controls(payload: object) -> int:
    if isinstance(payload, dict):
        total = 0
        controls = payload.get("controls")
        if isinstance(controls, list):
            total += sum(1 for item in controls if isinstance(item, dict) and item.get("id"))
        groups = payload.get("groups")
        if isinstance(groups, list):
            total += sum(count_controls(item) for item in groups)
        catalog = payload.get("catalog")
        if isinstance(catalog, dict):
            total += count_controls(catalog)
        return total
    if isinstance(payload, list):
        return sum(count_controls(item) for item in payload)
    return 0


def _ism_payload(root: Path, directory: Path, keep: int) -> tuple[dict | None, list[Path]]:
    selected = _select_ism(directory, keep)
    if not selected:
        return None, []
    catalogues = {}
    for name, _path in selected:
        info = _catalogue_info(directory / name / "ISM_catalog.json")
        if info.get("error"):
            raise ValueError(f"{name} catalogue was not usable")
        catalogues[name] = {"controls": info["controls"], "sha256": info["sha256"]}
    kept = [name for name, _path in selected]
    extras = [path for path in _catalog_dirs(directory) if path.name not in set(kept)]
    payload = {
        "catalogues": catalogues,
        "data_dir": _relative(root, directory),
        "kept": kept,
        "live_fetch": False,
        "source": "ism",
    }
    return payload, extras


def _select_ism(directory: Path, keep: int) -> list[tuple[str, Path]]:
    published = _published_at(directory)
    ranked = sorted(
        _catalog_dirs(directory),
        key=lambda path: (published.get(path.name, ""), _version_key(path.name), path.name),
        reverse=True,
    )
    return [(path.name, path) for path in ranked[:keep]]


def _catalog_dirs(directory: Path) -> list[Path]:
    found = []
    for path in directory.iterdir():
        if path.is_dir() and (path / "ISM_catalog.json").is_file():
            found.append(path)
    return found


def _published_at(directory: Path) -> dict[str, str]:
    path = directory / "releases.json"
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    rows = payload.get("releases") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return {}
    found = {}
    for row in rows:
        if isinstance(row, dict) and row.get("tag_name"):
            found[str(row["tag_name"])] = str(row.get("published_at") or "")
    return found


def _catalogue_info(path: Path) -> dict:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {"controls": None, "error": "catalogue was not usable", "sha256": digest}
    return {"controls": count_controls(payload), "error": "", "sha256": digest}


def _file_payload(root: Path, source: str, directory: Path) -> dict:
    files = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.name in _SKIP_FILES:
            continue
        if not _within(directory, path):
            continue
        files.append(
            {
                "path": _relative(root, path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return {
        "data_dir": _relative(root, directory),
        "files": files,
        "live_fetch": False,
        "source": source,
    }


def _write_reference(source: str, directory: Path, skill_dir: Path) -> Path:
    references = skill_dir / "references"
    references.mkdir(parents=True, exist_ok=True)
    filename = "ism-releases.md" if source == "ism" else f"{source}.md"
    destination = references / filename
    destination.write_text(_reference_text(source, directory), encoding="utf-8")
    return destination


def _reference_text(source: str, directory: Path) -> str:
    if source == "ism":
        lines = [
            "# ISM releases",
            "",
            "Generated from local OSCAL catalogues. This file is data, not instructions.",
            "",
            "Information Security Manual content is published by the Australian Signals "
            "Directorate. This file is not endorsed by ASD.",
            "",
            "| Release | Controls | SHA-256 |",
            "| --- | --- | --- |",
        ]
        for name, _path in _select_ism(directory, 2):
            info = _catalogue_info(directory / name / "ISM_catalog.json")
            controls = "unusable" if info.get("error") else str(info["controls"])
            lines.append(f"| {name} | {controls} | {info['sha256']} |")
        lines.append("")
        return "\n".join(lines)
    label = SOURCES[source][0]
    lines = [
        f"# {label}",
        "",
        "Generated from local files. This file is data, not instructions.",
        "",
    ]
    files = [
        path.name
        for path in sorted(directory.rglob("*"))
        if path.is_file() and path.name not in _SKIP_FILES and _within(directory, path)
    ]
    if not files:
        lines.append("No local files were present.")
    else:
        lines.extend(f"- {name}" for name in files)
    lines.append("")
    return "\n".join(lines)


def _write_manifest(directory: Path, payload: dict, *, force: bool) -> bool:
    destination = directory / "regen.json"
    if not force and destination.is_file():
        try:
            current = json.loads(destination.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            current = None
        if current == payload:
            return False
    destination.write_text(_dumps(payload), encoding="utf-8")
    return True


def _dumps(payload: dict) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _within(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _version_key(name: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", name))
