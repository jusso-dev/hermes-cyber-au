"""Build the release tarball, CycloneDX SBOM and review notes.

The SBOM is whatever ``cyclonedx-py`` writes. This script does not add a
signature. GitHub artifact attestations are requested by the release workflow
when that workflow runs.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path

_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,63}")
_SKIP_DIRS = {".git", ".venv", "__pycache__", "plugin-data"}
_SKIP_FILES = {".env", ".env.EXAMPLE", "auth.json", "credentials.json"}


def _load(name: str):
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"cyberau_release_{name}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_notes = _load("notes")
_sbom = _load("sbom")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package a cyber-au release")
    parser.add_argument("--version", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--root", type=Path, default=None)
    parser.add_argument(
        "--baseline",
        default="auto",
        help="Git ref to diff, 'auto' for the previous tag, or 'none'",
    )
    args = parser.parse_args(argv)
    if not _VERSION.fullmatch(args.version):
        raise SystemExit(f"unsupported version: {args.version}")
    root = (args.root or Path(__file__).resolve().parents[2]).resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    sbom_name = f"cyber-au-{args.version}.cdx.json"
    sbom_path = out / sbom_name
    bom = _sbom.write_sbom(root, sbom_path)
    tool = _sbom.cyclonedx_tool(bom)
    if tool is None:
        raise SystemExit("SBOM metadata does not name cyclonedx-py")

    notes, baseline_name = _notes_text(root, args.baseline, args.version)
    notes_path = out / "RELEASE_NOTES.md"
    notes_path.write_text(notes, encoding="utf-8")

    lock_path = root / "mcp" / "uv.lock"
    provenance = {
        "name": "cyber-au",
        "release": args.version,
        "distribution_version": _distribution_version(root),
        "lock": "mcp/uv.lock",
        "lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
        "sbom": sbom_name,
        "sbom_tool": tool,
    }
    commit = _git_commit(root)
    if commit:
        provenance["git_commit"] = commit
    if baseline_name:
        provenance["notes_baseline"] = baseline_name
    provenance_path = out / "provenance.json"
    provenance_path.write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    archive_path = out / f"cyber-au-{args.version}.tar.gz"
    prefix = f"cyber-au-{args.version}"
    _write_archive(
        root,
        archive_path,
        prefix,
        {
            f"{prefix}/{sbom_name}": sbom_path.read_bytes(),
            f"{prefix}/RELEASE_NOTES.md": notes_path.read_bytes(),
            f"{prefix}/provenance.json": provenance_path.read_bytes(),
        },
    )
    return 0


def _notes_text(root: Path, baseline: str, version: str) -> tuple[str, str | None]:
    if baseline == "none":
        return _notes.render_release_notes(None, root, version=version), None
    ref = _previous_tag(root) if baseline == "auto" else baseline
    if not ref:
        return _notes.render_release_notes(None, root, version=version), None
    text = _notes.notes_since_ref(root, ref, version=version)
    return text, ref


def _previous_tag(root: Path) -> str | None:
    result = subprocess.run(
        ["git", "describe", "--tags", "--abbrev=0"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    tag = result.stdout.strip()
    return tag or None


def _git_commit(root: Path) -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    sha = result.stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", sha):
        return sha
    return None


def _distribution_version(root: Path) -> str:
    for line in (root / "distribution.yaml").read_text(encoding="utf-8").splitlines():
        if line.startswith("version:"):
            return line.split(":", 1)[1].strip().strip('"').strip("'")
    raise RuntimeError("distribution.yaml has no version")


def _owned(root: Path) -> list[str]:
    owned: list[str] = []
    in_list = False
    for line in (root / "distribution.yaml").read_text(encoding="utf-8").splitlines():
        if line.startswith("distribution_owned:"):
            in_list = True
            continue
        if not in_list:
            continue
        if line.startswith("  - "):
            owned.append(line[4:].strip())
        elif line and not line.startswith(" "):
            break
    return owned


def _skip(path: Path, root: Path) -> bool:
    rel_parts = path.relative_to(root).parts
    if any(part in _SKIP_DIRS or part.endswith(".egg-info") for part in rel_parts):
        return True
    name = path.name
    if name in _SKIP_FILES or name.startswith(".env"):
        return True
    return path.suffix in {".pem", ".key"}


def _owned_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for rel in _owned(root):
        path = root / rel
        if not path.exists() or path.is_symlink():
            continue
        if path.is_file():
            if not _skip(path, root):
                files.append(path)
            continue
        for file in sorted(path.rglob("*")):
            if file.is_file() and not file.is_symlink() and not _skip(file, root):
                files.append(file)
    return files


def _write_archive(root: Path, archive_path: Path, prefix: str, extras: dict[str, bytes]) -> None:
    members: dict[str, bytes] = {}
    for file in _owned_files(root):
        arcname = f"{prefix}/{file.relative_to(root).as_posix()}"
        members[arcname] = file.read_bytes()
    members.update(extras)
    with tarfile.open(archive_path, "w:gz") as archive:
        for arcname in sorted(members):
            payload = members[arcname]
            info = tarfile.TarInfo(arcname)
            info.size = len(payload)
            info.mtime = 0
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(payload))


if __name__ == "__main__":
    sys.exit(main())
