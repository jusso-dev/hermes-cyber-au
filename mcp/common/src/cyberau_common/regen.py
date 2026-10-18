"""Regenerate the reference data that connectors ship and skills read.

``cyberau-mcp regen <source>`` checks the shipped data directory and writes a
manifest of file hashes. With ``--fetch`` it first downloads the upstream
source again through the connector's own ``rebuild_shipped_snapshot``, so the
connector's egress policy and rate limits apply. This module does no network
I/O itself.

A fetch that only changes retrieval dates is discarded unless the shipped copy
is older than ``RESTAMP_DAYS``, so the nightly workflow opens a pull request
when upstream changed, or when the copy needs a new date before it expires.
A missing data directory is an error.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

from cyberau_common.snapshot import parse_day

PARSER_CHECK_ABSENT = "parser-check is absent: not part of the shared library yet"

# Refresh the retrieval date of unchanged data once it is this old. Connectors
# refuse shipped reference data after 180 days, so this leaves plenty of margin.
RESTAMP_DAYS = 30


@dataclass(frozen=True)
class Source:
    label: str
    data_dir: str
    module: str
    skill: str | None = None


# Every directory here exists in the checkout. ATT&CK and Sigma are not shipped:
# those connectors fetch live and keep their own cache.
SOURCES: dict[str, Source] = {
    "ism": Source("ISM", "mcp/asd-ism/data", "cyberau_asd_ism.source", "ism-control-lookup"),
    "e8": Source(
        "Essential Eight",
        "mcp/asd-essentials/data",
        "cyberau_asd_essentials.source",
        "essentials-assessment",
    ),
    "aureg": Source(
        "AU reporting obligations", "mcp/au-regulatory/data", "cyberau_au_regulatory.source"
    ),
}

_SKIP_FILES = {"regen.json", ".DS_Store"}
_DATE_KEYS = {"retrieved_on", "retrieved_at", "as_of", "data_as_of"}
_DATE_IN_NAME = re.compile(r"\d{4}-\d{2}-\d{2}")


def missing_message(source: str) -> str:
    spec = SOURCES[source]
    return f"{spec.label} data directory {spec.data_dir} is missing."


def regen_main(argv: list[str], root: Path | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyberau-mcp regen")
    parser.add_argument("source")
    parser.add_argument("--keep", type=int, default=2)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--fetch", action="store_true", help="Download upstream data first")
    args = parser.parse_args(argv)
    if args.keep < 1:
        print("keep must be at least 1", file=sys.stderr)
        return 2
    if args.source not in SOURCES:
        print(f"regen does not know {args.source}.", file=sys.stderr)
        return 2
    base = Path.cwd() if root is None else root
    try:
        return regenerate(base, args.source, keep=args.keep, force=args.force, fetch=args.fetch)
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"regen {args.source} failed: {exc}", file=sys.stderr)
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


def regenerate(
    root: Path,
    source: str,
    *,
    keep: int = 2,
    force: bool = False,
    fetch: bool = False,
    today: date | None = None,
) -> int:
    spec = SOURCES[source]
    directory = locate(root, source)
    if directory is None:
        print(missing_message(source), file=sys.stderr)
        return 1
    relative = _relative(root, directory)
    fetched = ""
    if fetch:
        fetched = _fetch(source, directory, keep=keep, today=today)
        print(fetched)
    if source == "ism":
        payload, removals = _ism_payload(root, directory, keep)
        for extra in removals:
            if not _within(directory, extra):
                raise ValueError(f"refusing to remove {extra.name}")
        if payload is None:
            print(f"{spec.label} data directory has no catalogues.", file=sys.stderr)
            return 1
        for extra in removals:
            shutil.rmtree(extra)
        kept = ", ".join(payload["kept"])
        written = _write_manifest(directory, payload, force=force)
        if written or removals:
            print(f"Regenerated {spec.label} data in {relative} (kept {kept}).")
        else:
            print(f"{spec.label} data is unchanged.")
        return 0
    payload = _file_payload(root, source, directory)
    if not payload["files"]:
        print(f"{spec.label} data directory {relative} has no files.", file=sys.stderr)
        return 1
    written = _write_manifest(directory, payload, force=force)
    if written:
        print(f"Regenerated {spec.label} data in {relative}.")
    else:
        print(f"{spec.label} data is unchanged.")
    return 0


def _fetch(source: str, directory: Path, *, keep: int, today: date | None) -> str:
    """Rebuild into a scratch copy, then keep it only if it is worth a pull request."""
    spec = SOURCES[source]
    module = importlib.import_module(spec.module)
    rebuild = getattr(module, "rebuild_shipped_snapshot", None)
    if rebuild is None:
        raise RuntimeError(f"{spec.module} has no rebuild_shipped_snapshot, so it cannot fetch")
    with tempfile.TemporaryDirectory(prefix=f"regen-{source}-") as scratch:
        work = Path(scratch) / "data"
        shutil.copytree(directory, work)
        if source == "ism":
            rebuild(work, keep=keep)
        else:
            rebuild(work)
        before = content_signature(directory)
        after = content_signature(work)
        age = data_age_days(directory, today=today)
        if before == after and age is not None and age < RESTAMP_DAYS:
            return f"{spec.label} upstream is unchanged since the shipped copy ({age} days old)."
        _replace_tree(work, directory)
    if before == after:
        return f"{spec.label} upstream is unchanged. Refreshed the retrieval date."
    return f"{spec.label} upstream changed. Wrote the new data."


def content_signature(directory: Path) -> str:
    """Hash of the data with retrieval dates removed, so a re-fetch of the same
    upstream content compares equal."""
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.name in _SKIP_FILES:
            continue
        name = _DATE_IN_NAME.sub("DATE", path.relative_to(directory).as_posix())
        digest.update(name.encode() + b"\0")
        digest.update(_without_dates(path) + b"\0")
    return digest.hexdigest()


def data_age_days(directory: Path, *, today: date | None = None) -> int | None:
    """Days since the newest retrieval date in the directory's JSON files."""
    newest: date | None = None
    for path in directory.rglob("*.json"):
        if path.name in _SKIP_FILES:
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        for key in _DATE_KEYS:
            day = parse_day(payload.get(key))
            if day is not None and (newest is None or day > newest):
                newest = day
    if newest is None:
        return None
    return ((today or datetime.now(UTC).date()) - newest).days


def _without_dates(path: Path) -> bytes:
    raw = path.read_bytes()
    if path.suffix != ".json":
        return raw
    try:
        payload = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError):
        return raw
    return json.dumps(_strip(payload), sort_keys=True).encode()


def _strip(value):
    if isinstance(value, dict):
        return {key: _strip(item) for key, item in value.items() if key not in _DATE_KEYS}
    if isinstance(value, list):
        return [_strip(item) for item in value]
    return value


def _replace_tree(source: Path, destination: Path) -> None:
    keep = {path.relative_to(source) for path in source.rglob("*") if path.is_file()}
    for path in sorted(destination.rglob("*"), reverse=True):
        relative = path.relative_to(destination)
        if path.is_file() and relative not in keep and path.name not in _SKIP_FILES:
            path.unlink()
        elif path.is_dir() and not any(path.iterdir()):
            path.rmdir()
    for relative in sorted(keep):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, target)


def locate(root: Path, source: str) -> Path | None:
    path = root / SOURCES[source].data_dir
    return path if path.is_dir() else None


def render_report(root: Path) -> str:
    lines = [
        "## Skill data regeneration",
        "",
        "Checked the reference data each connector ships. Fetched sources were "
        "downloaded through the connector's egress policy.",
        "",
    ]
    for source, spec in SOURCES.items():
        directory = locate(root, source)
        if directory is None:
            lines.append(f"- {missing_message(source)}")
            continue
        lines.append(f"- {spec.label}: using {_relative(root, directory)}")
        if spec.skill is None:
            continue
        skill_dir = root / "skills" / spec.skill
        if not skill_dir.is_dir():
            lines.append(
                f"- Skill directory skills/{spec.skill} is absent. Not writing references."
            )
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
    label = SOURCES[source].label
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
