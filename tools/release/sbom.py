"""CycloneDX SBOM for the locked runtime dependencies.

Released cyclonedx-py does not read uv.lock. The packaging step exports the
lock with ``uv export --frozen`` and runs ``cyclonedx-py requirements`` on
that file. The SBOM written here is the document cyclonedx-py emits.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path


def runtime_packages(lock_path: Path) -> list[tuple[str, str]]:
    """Registry packages reachable from workspace runtime dependencies.

    The development group (pytest, ruff and their dependencies) is excluded.
    Workspace members are the distribution itself, so they are not listed here.
    """
    packages = tomllib.loads(lock_path.read_text(encoding="utf-8"))["package"]
    by_name: dict[str, list[dict]] = {}
    for package in packages:
        by_name.setdefault(package["name"], []).append(package)

    queue: list[str] = []
    for package in packages:
        source = package.get("source") or {}
        if "editable" not in source and "virtual" not in source:
            continue
        for dep in package.get("dependencies") or []:
            queue.append(dep["name"])

    seen: set[str] = set()
    runtime: list[tuple[str, str]] = []
    while queue:
        name = queue.pop()
        if name in seen:
            continue
        seen.add(name)
        for package in by_name.get(name, []):
            source = package.get("source") or {}
            if "registry" in source:
                runtime.append((package["name"], package["version"]))
            for dep in package.get("dependencies") or []:
                queue.append(dep["name"])
    runtime.sort()
    return runtime


def registry_hash_gaps(lock_path: Path) -> list[str]:
    """Names of registry archives in the lock that lack a sha256 hash."""
    gaps: list[str] = []
    packages = tomllib.loads(lock_path.read_text(encoding="utf-8"))["package"]
    for package in packages:
        source = package.get("source") or {}
        if "registry" not in source:
            continue
        archives: list[dict] = []
        if package.get("sdist"):
            archives.append(package["sdist"])
        archives.extend(package.get("wheels") or [])
        label = f"{package['name']}=={package['version']}"
        if not archives:
            gaps.append(label)
            continue
        for archive in archives:
            digest = str(archive.get("hash") or "")
            if not digest.startswith("sha256:"):
                gaps.append(label)
                break
    return gaps


def write_sbom(root: Path, dest: Path) -> dict:
    """Write a CycloneDX JSON document and return it."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    requirements = dest.with_suffix(".requirements.txt")
    project = root / "mcp"
    try:
        export = subprocess.run(
            [
                _uv(),
                "export",
                "--project",
                str(project),
                "--frozen",
                "--offline",
                "--all-packages",
                "--no-dev",
                "--no-emit-workspace",
                "--no-header",
                # No --format: uv 0.6 spells it requirements-txt and later releases
                # requirements.txt, but every release defaults to that format.
                "-o",
                str(requirements),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        if export.returncode != 0:
            detail = export.stderr.strip() or export.stdout.strip() or "uv export failed"
            raise RuntimeError(detail)
        generated = subprocess.run(
            [
                str(_cyclonedx_py()),
                "requirements",
                str(requirements),
                "--output-reproducible",
                "--sv",
                "1.6",
                "--of",
                "JSON",
                "--pyproject",
                str(project / "pyproject.toml"),
                "--mc-type",
                "application",
                "-o",
                str(dest),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        if generated.returncode != 0:
            detail = generated.stderr.strip() or generated.stdout.strip() or "cyclonedx-py failed"
            raise RuntimeError(detail)
        bom = json.loads(dest.read_text(encoding="utf-8"))
    finally:
        requirements.unlink(missing_ok=True)
    if cyclonedx_tool(bom) is None:
        raise RuntimeError("cyclonedx-py did not record itself in the SBOM metadata")
    return bom


def cyclonedx_tool(bom: dict) -> str | None:
    """Return ``cyclonedx-py <version>`` when that tool produced the document."""
    tools = (bom.get("metadata") or {}).get("tools") or {}
    components = tools.get("components") if isinstance(tools, dict) else tools
    if not isinstance(components, list):
        return None
    for component in components:
        if component.get("name") == "cyclonedx-py":
            version = component.get("version")
            return f"cyclonedx-py {version}" if version else "cyclonedx-py"
    return None


def _uv() -> str:
    found = shutil.which("uv")
    if not found:
        raise RuntimeError("uv is not on PATH")
    return found


def _cyclonedx_py() -> Path:
    beside = Path(sys.executable).with_name("cyclonedx-py")
    if beside.is_file():
        return beside
    found = shutil.which("cyclonedx-py")
    if found:
        return Path(found)
    raise RuntimeError("cyclonedx-py is not installed in this environment")
