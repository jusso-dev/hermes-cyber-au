"""Build the offline install bundle: one tarball an air-gapped host can install from.

Layout of ``cyber-au-offline-<version>.tar.gz``::

    cyber-au-offline-<version>/
      install-offline.sh          offline installer (install/offline-install.sh)
      profile/install/install.sh  the normal installer, run with --offline
      bundle.json                 version, platforms, Python versions, lock hash
      SHA256SUMS                  every other file in the bundle
      profile/                    the distribution-owned files, the profile Hermes installs
      profile/intel/snapshots/    public intel store snapshots present at build time
      requirements/runtime.txt    ``uv export --frozen`` of mcp/uv.lock, with hashes
      requirements/build.txt      hatchling and editables, with hashes (editable installs)
      requirements/workspace.txt  workspace member directories under mcp/
      requirements/python-versions.txt  Python versions the wheels were chosen for
      requirements/plugin.txt     the plugin's Hermes-side dependencies
      wheels/<platform>/          wheels for every runtime requirement
      wheels/<platform>/plugin/   wheels for the plugin's Hermes-side dependencies

Only this script talks to the network, and only through ``exporter``,
``resolver`` and ``downloader``. Tests replace all three. Run it on Linux: pip
evaluates environment markers such as ``sys_platform`` against the machine it
runs on, and only the wheel tags against ``--platform``.

The bundle is not signed here. The release workflow attests it with
``actions/attest-build-provenance`` (Sigstore keyless). See docs/operations/offline.md.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,63}")
_PYTHON = re.compile(r"3\.\d{1,2}")

PLATFORMS: dict[str, str] = {"linux_x86_64": "x86_64", "linux_aarch64": "aarch64"}
DEFAULT_PYTHONS = ("3.12",)
# Wheels built for glibc 2.17 up to 2.28 install on RHEL 8, Debian 10 and newer.
GLIBC_MINORS = range(17, 29)
# Build backend for the editable workspace installs. Resolved and hashed at build time.
BUILD_REQUIREMENTS = ("hatchling>=1.27,<2", "editables>=0.5,<1")
# Plugin dependencies go into the Python that runs Hermes, which may differ from 3.12.
PLUGIN_PYTHONS = ("3.11", "3.12", "3.13", "3.14")

Exporter = Callable[[Path], str]
Resolver = Callable[[Sequence[str], str, Path], str]
Downloader = Callable[[Path, Path, str, str, bool], None]


def _load_package():
    path = Path(__file__).resolve().parent / "package.py"
    spec = importlib.util.spec_from_file_location("cyberau_release_package_for_bundle", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def platform_tags(platform: str) -> list[str]:
    arch = PLATFORMS[platform]
    tags = [f"manylinux_2_{minor}_{arch}" for minor in GLIBC_MINORS]
    tags.append(f"manylinux2014_{arch}")
    return tags


# Network steps. Each is replaceable.


def uv_export(root: Path) -> str:
    """Runtime requirements with hashes, straight from mcp/uv.lock."""
    uv = shutil.which("uv")
    if not uv:
        raise RuntimeError("uv is not on PATH")
    result = subprocess.run(
        [
            uv,
            "export",
            "--project",
            str(root / "mcp"),
            "--frozen",
            "--offline",
            "--all-packages",
            "--no-dev",
            "--no-emit-workspace",
            "--no-header",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "uv export failed")
    return result.stdout


def uv_resolve(requirements: Sequence[str], python_version: str, constraints: Path) -> str:
    """Pin and hash ``requirements`` for Linux, held to the versions in ``constraints``.

    Uses the network at release time."""
    uv = shutil.which("uv")
    if not uv:
        raise RuntimeError("uv is not on PATH")
    with tempfile.TemporaryDirectory(prefix="cyberau-bundle-") as tmp:
        spec = Path(tmp) / "in.txt"
        spec.write_text("\n".join(requirements) + "\n", encoding="utf-8")
        result = subprocess.run(
            [
                uv,
                "pip",
                "compile",
                str(spec),
                "--constraint",
                str(constraints),
                "--generate-hashes",
                "--no-header",
                "--only-binary",
                ":all:",
                "--python-version",
                python_version,
                "--python-platform",
                "linux",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "uv pip compile failed")
    return result.stdout


def pip_download(
    requirements: Path, dest: Path, platform: str, python_version: str, hashed: bool
) -> None:
    """``pip download --only-binary=:all:`` for one Linux platform and Python version."""
    command = [
        _pip_python(),
        "-m",
        "pip",
        "download",
        "--disable-pip-version-check",
        "--no-deps",
        "--only-binary=:all:",
        "--implementation",
        "cp",
        "--python-version",
        python_version,
        "--dest",
        str(dest),
        "-r",
        str(requirements),
    ]
    if hashed:
        command.append("--require-hashes")
    for tag in platform_tags(platform):
        command.extend(["--platform", tag])
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "pip download failed"
        raise RuntimeError(f"{platform} python {python_version}: {detail}")


def _pip_python() -> str:
    probe = subprocess.run(
        [sys.executable, "-m", "pip", "--version"], capture_output=True, check=False
    )
    if probe.returncode == 0:
        return sys.executable
    for name in ("python3", "python"):
        found = shutil.which(name)
        if found:
            return found
    raise RuntimeError("no Python with pip is available for pip download")


# Build


def build_bundle(
    root: Path,
    version: str,
    out: Path,
    *,
    platforms: Iterable[str] = tuple(PLATFORMS),
    python_versions: Iterable[str] = DEFAULT_PYTHONS,
    exporter: Exporter = uv_export,
    resolver: Resolver = uv_resolve,
    downloader: Downloader = pip_download,
) -> Path:
    if not _VERSION.fullmatch(version):
        raise ValueError(f"unsupported version: {version}")
    platforms = list(platforms)
    pythons = list(python_versions)
    unknown = [item for item in platforms if item not in PLATFORMS]
    if unknown or not platforms:
        raise ValueError(f"unsupported platform: {', '.join(unknown) or 'none given'}")
    if not pythons or any(not _PYTHON.fullmatch(item) for item in pythons):
        raise ValueError(f"unsupported Python version list: {pythons}")
    root = root.resolve()
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    package = _load_package()
    name = f"cyber-au-offline-{version}"

    with tempfile.TemporaryDirectory(prefix="cyberau-bundle-") as tmp:
        stage = Path(tmp) / name
        profile = stage / "profile"
        for file in package._owned_files(root):
            _copy(file, profile / file.relative_to(root))
        for file in _intel_snapshots(root):
            _copy(file, profile / file.relative_to(root))
        # install.sh is not distribution-owned. In the bundle it sits beside bootstrap.sh
        # so it treats profile/ as the checkout to install from.
        _copy(root / "install" / "install.sh", profile / "install" / "install.sh")

        requirements = stage / "requirements"
        requirements.mkdir(parents=True)
        runtime = requirements / "runtime.txt"
        runtime.write_text(exporter(root), encoding="utf-8")
        build = requirements / "build.txt"
        build.write_text(resolver(BUILD_REQUIREMENTS, pythons[0], runtime), encoding="utf-8")
        members = workspace_members(root)
        (requirements / "workspace.txt").write_text("\n".join(members) + "\n", encoding="utf-8")
        (requirements / "python-versions.txt").write_text(
            "\n".join(pythons) + "\n", encoding="utf-8"
        )
        plugin_deps = _plugin_dependencies(root)
        plugin = requirements / "plugin.txt"
        plugin.write_text("\n".join(plugin_deps) + ("\n" if plugin_deps else ""), encoding="utf-8")

        for platform in platforms:
            wheels = stage / "wheels" / platform
            wheels.mkdir(parents=True)
            for python_version in pythons:
                downloader(runtime, wheels, platform, python_version, True)
                downloader(build, wheels, platform, python_version, True)
            if plugin_deps:
                (wheels / "plugin").mkdir()
                for python_version in PLUGIN_PYTHONS:
                    downloader(plugin, wheels / "plugin", platform, python_version, False)
            if not any(wheels.glob("*.whl")):
                raise RuntimeError(f"no wheels were downloaded for {platform}")

        installer = root / "install" / "offline-install.sh"
        _copy(installer, stage / "install-offline.sh")
        lock = root / "mcp" / "uv.lock"
        manifest = {
            "name": "cyber-au-offline",
            "release": version,
            "distribution_version": package._distribution_version(root),
            "platforms": platforms,
            "python_versions": pythons,
            "plugin_python_versions": list(PLUGIN_PYTHONS) if plugin_deps else [],
            "lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
            "workspace_members": len(members),
            "wheels": {
                platform: len(list((stage / "wheels" / platform).rglob("*.whl")))
                for platform in platforms
            },
        }
        commit = package._git_commit(root)
        if commit:
            manifest["git_commit"] = commit
        (stage / "bundle.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (stage / "SHA256SUMS").write_text(_sums(stage), encoding="utf-8")
        archive = out / f"{name}.tar.gz"
        _write_tar(stage, archive, name)
    return archive


def workspace_members(root: Path) -> list[str]:
    data = tomllib.loads((root / "mcp" / "pyproject.toml").read_text(encoding="utf-8"))
    members = data.get("tool", {}).get("uv", {}).get("workspace", {}).get("members", [])
    found: list[str] = []
    for member in members:
        if not isinstance(member, str) or not re.fullmatch(r"[a-z][a-z0-9-]*", member):
            raise ValueError(f"unexpected workspace member {member!r}")
        if (root / "mcp" / member / "pyproject.toml").is_file():
            found.append(member)
    if not found:
        raise ValueError("mcp/pyproject.toml lists no workspace members")
    return found


def _plugin_dependencies(root: Path) -> list[str]:
    manifest = root / "plugins" / "cyber-au" / "plugin.yaml"
    if not manifest.is_file():
        return []
    deps: list[str] = []
    active = False
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if line.startswith("python_dependencies:"):
            active = True
            continue
        if active:
            stripped = line.strip()
            if stripped.startswith("- "):
                deps.append(stripped[2:].strip().strip('"').strip("'"))
            elif stripped and not line.startswith(" "):
                break
    return deps


def _intel_snapshots(root: Path) -> list[Path]:
    directory = root / "intel" / "snapshots"
    if not directory.is_dir():
        return []
    return [
        file
        for file in sorted(directory.glob("public-*.sqlite.zst"))
        if file.is_file() and not file.is_symlink()
    ]


def _copy(source: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, dest)


def _sums(stage: Path) -> str:
    lines = []
    for file in sorted(stage.rglob("*")):
        if not file.is_file() or file.name == "SHA256SUMS" and file.parent == stage:
            continue
        digest = hashlib.sha256(file.read_bytes()).hexdigest()
        lines.append(f"{digest}  {file.relative_to(stage).as_posix()}")
    return "\n".join(lines) + "\n"


def _write_tar(stage: Path, archive: Path, prefix: str) -> None:
    executable = {
        "install-offline.sh",
        "profile/install/install.sh",
        "profile/install/bootstrap.sh",
    }
    with tarfile.open(archive, "w:gz") as tar:
        for file in sorted(stage.rglob("*")):
            if not file.is_file():
                continue
            rel = file.relative_to(stage).as_posix()
            payload = file.read_bytes()
            info = tarfile.TarInfo(f"{prefix}/{rel}")
            info.size = len(payload)
            info.mtime = 0
            info.mode = 0o755 if rel in executable else 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(payload))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the cyber-au offline install bundle")
    parser.add_argument("--version", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--root", type=Path, default=None)
    parser.add_argument(
        "--platform",
        action="append",
        choices=sorted(PLATFORMS),
        help="Repeat for each platform. Default: linux_x86_64 and linux_aarch64",
    )
    parser.add_argument(
        "--python-version",
        action="append",
        help="Target Python for the connector venv. Repeat. Default: 3.12",
    )
    args = parser.parse_args(argv)
    root = args.root or Path(__file__).resolve().parents[2]
    archive = build_bundle(
        root,
        args.version,
        args.out,
        platforms=args.platform or tuple(PLATFORMS),
        python_versions=args.python_version or DEFAULT_PYTHONS,
    )
    print(archive)
    return 0


if __name__ == "__main__":
    sys.exit(main())
