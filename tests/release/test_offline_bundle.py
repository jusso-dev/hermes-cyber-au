"""Offline bundle: builder layout and an install from a fake wheelhouse. No network.

The builder's three network steps (uv export, uv pip compile, pip download) are
replaced. The install test runs install/offline-install.sh from a bundle built from a
small synthetic distribution. Its wheels are made here, including a tiny PEP 660 build
backend, so pip never needs an index. curl, git and uv on PATH are stubs that fail and
log, and the proxy variables point at a closed port, so any attempt to reach the
network fails the test.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PY = f"{sys.version_info.major}.{sys.version_info.minor}"


def _load(name: str):
    path = ROOT / "tools" / "release" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"cyberau_release_{name}_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


bundle = _load("offline_bundle")


# Fake wheels


def _record_hash(payload: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()


def _wheel(dest: Path, name: str, version: str, files: dict[str, str]) -> Path:
    """Write a minimal valid pure-Python wheel."""
    norm = name.replace("-", "_")
    dist = f"{norm}-{version}.dist-info"
    members = {path: text.encode() for path, text in files.items()}
    members[f"{dist}/METADATA"] = (
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode()
    )
    members[f"{dist}/WHEEL"] = (
        b"Wheel-Version: 1.0\nGenerator: offline-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    )
    record = [f"{path},sha256={_record_hash(data)},{len(data)}" for path, data in members.items()]
    record.append(f"{dist}/RECORD,,")
    members[f"{dist}/RECORD"] = ("\n".join(record) + "\n").encode()
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / f"{norm}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        for member, data in members.items():
            archive.writestr(member, data)
    return path


# A PEP 660 backend just big enough for pip install -e --no-build-isolation.
BACKEND = """
import base64, hashlib, os, tomllib, zipfile


def _line(name, data):
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{name},sha256={digest},{len(data)}"


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    with open("pyproject.toml", "rb") as handle:
        project = tomllib.load(handle)["project"]
    name = project["name"].replace("-", "_")
    version = project["version"]
    dist = f"{name}-{version}.dist-info"
    metadata = f"Metadata-Version: 2.1\\nName: {project['name']}\\nVersion: {version}\\n"
    wheel = "Wheel-Version: 1.0\\nGenerator: offline-test\\nRoot-Is-Purelib: true\\n"
    files = {
        f"{name}.pth": (os.path.abspath("src") + "\\n").encode(),
        f"{dist}/METADATA": metadata.encode(),
        f"{dist}/WHEEL": (wheel + "Tag: py3-none-any\\n").encode(),
    }
    scripts = project.get("scripts") or {}
    if scripts:
        body = "".join(f"{key} = {value}\\n" for key, value in scripts.items())
        files[f"{dist}/entry_points.txt"] = ("[console_scripts]\\n" + body).encode()
    record = [_line(key, value) for key, value in files.items()] + [f"{dist}/RECORD,,"]
    files[f"{dist}/RECORD"] = ("\\n".join(record) + "\\n").encode()
    filename = f"{name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(os.path.join(wheel_directory, filename), "w") as archive:
        for key, value in files.items():
            archive.writestr(key, value)
    return filename


build_wheel = build_editable
"""

STUB_CLI = """
import os, sys


def main():
    log = os.environ.get("CYBERAU_STUB_LOG")
    if log:
        with open(log, "a", encoding="utf-8") as handle:
            handle.write(" ".join(sys.argv[1:]) + "\\n")
    return 0
"""


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def wheelhouse(tmp_path: Path) -> dict[str, Path]:
    house = tmp_path / "prebuilt"
    return {
        # The fake runtime dependency also carries a .pth that adds this test runner's
        # site-packages, so render_config.py finds PyYAML without a real PyYAML wheel.
        "dep": _wheel(
            house,
            "offline-test-dep",
            "1.0",
            {
                "offline_test_dep.py": "VALUE = 1\n",
                "offline_test_dep_yaml.pth": str(Path(yaml.__file__).parent.parent) + "\n",
            },
        ),
        "backend": _wheel(
            house, "offline-test-backend", "1.0", {"offline_test_backend.py": BACKEND}
        ),
        "plugin": _wheel(
            house, "offline-test-plugin-dep", "1.0", {"offline_test_plugin_dep.py": "X = 1\n"}
        ),
    }


def _fakes(wheels: dict[str, Path], calls: list[tuple]):
    def exporter(_root: Path) -> str:
        calls.append(("export",))
        return f"offline-test-dep==1.0 \\\n    --hash=sha256:{_sha(wheels['dep'])}\n"

    def resolver(requirements, python_version, constraints) -> str:
        calls.append(("resolve", tuple(requirements), python_version, constraints.name))
        return f"offline-test-backend==1.0 \\\n    --hash=sha256:{_sha(wheels['backend'])}\n"

    def downloader(requirements: Path, dest: Path, platform: str, python: str, hashed: bool):
        calls.append(("download", requirements.name, platform, python, hashed))
        text = requirements.read_text(encoding="utf-8")
        for key, wheel in wheels.items():
            if wheel.name.split("-")[0].replace("_", "-") in text.replace("_", "-"):
                shutil.copy2(wheel, dest / wheel.name)

    return exporter, resolver, downloader


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def synthetic(tmp_path: Path) -> Path:
    """A small distribution with one workspace member that provides cyberau-mcp."""
    root = tmp_path / "dist-root"
    _write(
        root / "distribution.yaml",
        'name: cyber-au\nversion: 0.1.0\nhermes_requires: ">=0.1.0"\n'
        "distribution_owned:\n"
        "  - distribution.yaml\n  - config.yaml\n  - cron/jobs.json\n  - scripts\n"
        "  - plugins/cyber-au\n  - install/bootstrap.sh\n  - install/render_config.py\n"
        "  - mcp\n",
    )
    _write(root / "config.yaml", "model: {}\n")
    _write(root / "cron" / "jobs.json", '{"jobs": []}\n')
    (root / "install").mkdir()
    for name in ("install.sh", "bootstrap.sh", "render_config.py", "offline-install.sh"):
        shutil.copy2(ROOT / "install" / name, root / "install" / name)
    (root / "scripts").mkdir()
    shutil.copy2(
        ROOT / "scripts" / "cyberau_enable_maintenance.py",
        root / "scripts" / "cyberau_enable_maintenance.py",
    )
    _write(
        root / "plugins" / "cyber-au" / "plugin.yaml",
        "name: cyber-au\n"
        "python_dependencies:\n"
        '  - "offline-test-plugin-dep>=1,<2"\n'
        "provides_tools: []\n",
    )
    _write(
        root / "plugins" / "cyber-au" / "cli.py",
        "# doctor and migrate stand-in for the offline install test\nimport sys\nsys.exit(0)\n",
    )
    mcp = root / "mcp"
    _write(
        mcp / "pyproject.toml",
        '[project]\nname = "ws"\nversion = "0.1.0"\n\n[tool.uv.workspace]\nmembers = ["common"]\n',
    )
    _write(mcp / "uv.lock", "version = 1\n# synthetic lock for the offline install test\n")
    _write(
        mcp / "servers.yaml",
        "servers:\n  kev:\n    connector: common\n    args: [serve, common]\n    env: []\n"
        "    enabled_by_default: true\n    required_env: []\n",
    )
    _write(mcp / "egress-allowlist.yaml", "connectors: {}\n")
    _write(
        mcp / "common" / "pyproject.toml",
        '[project]\nname = "offline-test-common"\nversion = "0.1.0"\n'
        'dependencies = ["offline-test-dep"]\n\n[project.scripts]\n'
        'cyberau-mcp = "offline_test_common.cli:main"\n\n[build-system]\n'
        'requires = ["offline-test-backend"]\nbuild-backend = "offline_test_backend"\n',
    )
    _write(mcp / "common" / "src" / "offline_test_common" / "__init__.py", "")
    _write(mcp / "common" / "src" / "offline_test_common" / "cli.py", STUB_CLI)
    _write(mcp / "asd-ism" / "data" / "releases.json", "{}\n")
    _write(mcp / "asd-essentials" / "data" / "e8-maturity-test.json", "{}\n")
    _write(mcp / "asd-essentials" / "data" / "essentials-test.json", "{}\n")
    _write(root / "intel" / "snapshots" / "public-2026-11-27.sqlite.zst", "snapshot")
    return root


def _build(root: Path, out: Path, wheels, calls, **kwargs) -> Path:
    exporter, resolver, downloader = _fakes(wheels, calls)
    return bundle.build_bundle(
        root,
        "2026.11.28",
        out,
        exporter=exporter,
        resolver=resolver,
        downloader=downloader,
        **kwargs,
    )


def _unpack(archive: Path, dest: Path) -> Path:
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(dest, filter="data")
    (top,) = list(dest.iterdir())
    return top


def test_bundle_layout_checksums_and_download_calls(tmp_path, synthetic, wheelhouse):
    calls: list[tuple] = []
    archive = _build(synthetic, tmp_path / "out", wheelhouse, calls)
    assert archive.name == "cyber-au-offline-2026.11.28.tar.gz"
    top = _unpack(archive, tmp_path / "unpacked")

    manifest = json.loads((top / "bundle.json").read_text())
    assert manifest["platforms"] == ["linux_x86_64", "linux_aarch64"]
    assert manifest["python_versions"] == ["3.12"]
    assert manifest["lock_sha256"] == _sha(synthetic / "mcp" / "uv.lock")
    assert (top / "requirements" / "workspace.txt").read_text() == "common\n"
    assert (top / "requirements" / "python-versions.txt").read_text() == "3.12\n"
    assert "offline-test-plugin-dep" in (top / "requirements" / "plugin.txt").read_text()
    assert (top / "profile" / "intel" / "snapshots" / "public-2026-11-27.sqlite.zst").is_file()
    assert (top / "profile" / "mcp" / "asd-ism" / "data" / "releases.json").is_file()
    assert (top / "profile" / "install" / "install.sh").is_file()
    assert os.access(top / "install-offline.sh", os.X_OK)
    for platform in ("linux_x86_64", "linux_aarch64"):
        assert (top / "wheels" / platform / wheelhouse["dep"].name).is_file()
        assert (top / "wheels" / platform / "plugin" / wheelhouse["plugin"].name).is_file()

    lines = (top / "SHA256SUMS").read_text().splitlines()
    listed = {line.split("  ", 1)[1]: line.split("  ", 1)[0] for line in lines}
    files = {
        path.relative_to(top).as_posix()
        for path in top.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    assert set(listed) == files
    for rel, digest in listed.items():
        assert _sha(top / rel) == digest

    downloads = [call for call in calls if call[0] == "download"]
    hashed = {(c[1], c[2], c[3]) for c in downloads if c[4]}
    assert ("runtime.txt", "linux_x86_64", "3.12") in hashed
    assert ("runtime.txt", "linux_aarch64", "3.12") in hashed
    assert ("build.txt", "linux_aarch64", "3.12") in hashed
    plugin = {(c[2], c[3]) for c in downloads if c[1] == "plugin.txt"}
    assert ("linux_x86_64", "3.14") in plugin
    resolve = [call for call in calls if call[0] == "resolve"]
    assert resolve and resolve[0][3] == "runtime.txt"


def test_bundle_from_the_real_tree_ships_profile_and_data(tmp_path, wheelhouse):
    calls: list[tuple] = []
    archive = _build(ROOT, tmp_path / "out", wheelhouse, calls, platforms=["linux_x86_64"])
    with tarfile.open(archive, "r:gz") as tar:
        names = set(tar.getnames())
    prefix = "cyber-au-offline-2026.11.28/"
    assert prefix + "profile/distribution.yaml" in names
    assert prefix + "profile/install/bootstrap.sh" in names
    assert prefix + "profile/mcp/uv.lock" in names
    assert prefix + "profile/mcp/asd-ism/data/releases.json" in names
    assert prefix + "install-offline.sh" in names
    assert not any("/.venv/" in name or name.endswith("/.env") for name in names)
    members = (tmp_path / "out").glob("*.tar.gz")
    assert [path.name for path in members] == [archive.name]


def test_builder_rejects_unknown_platforms_and_versions(tmp_path, synthetic, wheelhouse):
    with pytest.raises(ValueError, match="platform"):
        _build(synthetic, tmp_path / "o", wheelhouse, [], platforms=["windows_x86"])
    with pytest.raises(ValueError, match="Python"):
        _build(synthetic, tmp_path / "o", wheelhouse, [], python_versions=["3"])
    with pytest.raises(ValueError, match="version"):
        bundle.build_bundle(synthetic, "../bad", tmp_path / "o")


def test_platform_tags_cover_manylinux():
    tags = bundle.platform_tags("linux_aarch64")
    assert "manylinux2014_aarch64" in tags
    assert "manylinux_2_28_aarch64" in tags
    assert all(tag.endswith("aarch64") for tag in tags)


# Install from the bundle


FAKE_HERMES = r"""#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_LOG"
profile=cyber-au
prev=
src=
for arg in "$@"; do
  case $prev in -p|--name) profile=$arg ;; esac
  if [ "$prev" = "install" ]; then src=$arg; fi
  case $arg in --version) printf '%s\n' "Hermes Agent 9.9.9"; exit 0 ;; esac
  prev=$arg
done
home="$HOME/.hermes/profiles/$profile"
case " $* " in
  *" config path "*) printf '%s\n' "$home/config.yaml"; exit 0 ;;
  *" plugins enable "*) exit 0 ;;
  *" cyber-au doctor "*) exit 0 ;;
esac
if [ -n "$src" ]; then
  mkdir -p "$home"
  cp -R "$src/." "$home/"
  # Hermes copies distribution-owned paths only. intel/ is not one of them.
  rm -rf "$home/intel"
  exit 0
fi
printf '%s\n' "unhandled hermes command: $*" >&2
exit 1
"""

NETWORK_STUB = """#!/bin/sh
printf '%s\\n' "$(basename "$0") $*" >> "$NETWORK_LOG"
printf '%s\\n' "network tool must not run during an offline install" >&2
exit 99
"""


def _env(tmp_path: Path) -> dict[str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "hermes").write_text(FAKE_HERMES)
    for name in ("curl", "wget", "git", "uv"):
        (bin_dir / name).write_text(NETWORK_STUB)
    for path in bin_dir.iterdir():
        path.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    hermes_venv = tmp_path / "hermes-venv"
    subprocess.run([sys.executable, "-m", "venv", str(hermes_venv)], check=True)
    dead = "http://127.0.0.1:9"
    return {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "HOME": str(home),
        "FAKE_LOG": str(tmp_path / "hermes.log"),
        "NETWORK_LOG": str(tmp_path / "network.log"),
        "CYBERAU_STUB_LOG": str(tmp_path / "cyberau-mcp.log"),
        "CYBERAU_PYTHON": sys.executable,
        "HERMES_PYTHON": str(hermes_venv / "bin" / "python"),
        "http_proxy": dead,
        "https_proxy": dead,
        "HTTP_PROXY": dead,
        "HTTPS_PROXY": dead,
        "ALL_PROXY": dead,
        "NO_PROXY": "",
        "PIP_CONFIG_FILE": os.devnull,
        "LANG": "C",
    }


def _run(top: Path, env: dict[str, str], *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "sh",
            str(top / "install-offline.sh"),
            "--platform",
            "linux_x86_64",
            "--non-interactive",
            "--yes",
            "--allow-root",
            *extra,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell installer")
def test_offline_install_from_a_fake_wheelhouse(tmp_path, synthetic, wheelhouse):
    archive = _build(synthetic, tmp_path / "out", wheelhouse, [], python_versions=[PY])
    top = _unpack(archive, tmp_path / "unpacked")
    env = _env(tmp_path)

    result = _run(top, env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Bundle files match SHA256SUMS." in result.stdout
    assert "Offline install finished for cyber-au." in result.stdout

    network_log = tmp_path / "network.log"
    assert not network_log.exists() or network_log.read_text() == ""

    home = Path(env["HOME"]) / ".hermes" / "profiles" / "cyber-au"
    venv_python = home / "mcp" / ".venv" / "bin" / "python"
    check = subprocess.run(
        [str(venv_python), "-c", "import offline_test_dep, offline_test_common.cli"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert check.returncode == 0, check.stderr
    assert (home / "mcp" / ".venv" / "bin" / "cyberau-mcp").is_file()
    stamp = (home / "mcp" / ".venv" / ".cyberau-lock-sha256").read_text().strip()
    assert stamp == _sha(home / "mcp" / "uv.lock")

    plugin = subprocess.run(
        [env["HERMES_PYTHON"], "-c", "import offline_test_plugin_dep"],
        capture_output=True,
        check=False,
    )
    assert plugin.returncode == 0

    env_file = home / ".env"
    assert "CYBERAU_OFFLINE=1" in env_file.read_text()
    assert env_file.stat().st_mode & 0o777 == 0o600
    config = yaml.safe_load((home / "config.yaml").read_text())
    assert config["mcp_servers"]["kev"]["env"]["CYBERAU_OFFLINE"] == "1"

    store_calls = (tmp_path / "cyberau-mcp.log").read_text()
    assert "store init" in store_calls
    assert (home / "intel" / "snapshots" / "public-2026-11-27.sqlite.zst").is_file()
    hermes_calls = (tmp_path / "hermes.log").read_text()
    assert "profile install" in hermes_calls
    assert "plugins enable cyber-au" in hermes_calls


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell installer")
def test_offline_install_refuses_a_changed_bundle(tmp_path, synthetic, wheelhouse):
    archive = _build(synthetic, tmp_path / "out", wheelhouse, [], python_versions=[PY])
    top = _unpack(archive, tmp_path / "unpacked")
    target = top / "profile" / "install" / "bootstrap.sh"
    target.write_text(target.read_text() + "\n# changed after release\n")
    env = _env(tmp_path)
    result = _run(top, env)
    assert result.returncode != 0
    assert "SHA256SUMS check failed" in result.stderr
    assert not (Path(env["HOME"]) / ".hermes").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell installer")
def test_offline_install_needs_a_bundled_python_version(tmp_path, synthetic, wheelhouse):
    other = "3.99"
    archive = _build(synthetic, tmp_path / "out", wheelhouse, [], python_versions=[other])
    top = _unpack(archive, tmp_path / "unpacked")
    env = _env(tmp_path)
    env.pop("CYBERAU_PYTHON")
    result = _run(top, env)
    assert result.returncode != 0
    assert "wheels for Python 3.99" in result.stderr


def test_release_workflow_builds_attests_and_tests_the_bundle():
    text = (ROOT / ".github" / "workflows" / "weekly-release.yml").read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    assert "tools/release/offline_bundle.py" in text
    steps = workflow["jobs"]["package"]["steps"]
    names = [step.get("name", "") for step in steps]
    # The bundle is built before the checksums and the attestation that signs it.
    build = next(i for i, step in enumerate(steps) if "offline_bundle.py" in step.get("run", ""))
    sums = names.index("Checksums")
    attest = names.index("Attest release files")
    assert build < sums < attest
    pack = next(step for step in steps if step.get("name") == "Build signed data pack")
    assert "secrets.CYBERAU_DATAPACK_SIGNING_KEY" in pack["env"]["DATAPACK_KEY"]
    assert 'rm -f "$key"' in pack["run"]
    assert "BEGIN PRIVATE KEY" not in text
    job = workflow["jobs"]["offline-install"]
    assert job["runs-on"] == "ubuntu-latest"
    assert job["continue-on-error"] is True
    assert job["permissions"] == {"contents": "read"}
    assert "offline_container_test.sh" in json.dumps(job)
    assert "codebuild" not in text.lower()
    script = (ROOT / "tools" / "ci" / "offline_container_test.sh").read_text(encoding="utf-8")
    assert "--network none" in script
    assert re.search(r"python:3\.12-slim@sha256:[0-9a-f]{64}", script)


def test_datapack_build_runs_with_the_cli_flags_the_workflow_uses(tmp_path):
    from cyberau_common import datapack

    private = tmp_path / "keys" / "k.key"
    datapack.generate_keypair(private, tmp_path / "keys" / "k.pub")
    out = tmp_path / "dist" / "cyber-au-datapack-2026.11.28.tar.gz"
    code = datapack.main(
        [
            "build",
            "--key",
            str(private),
            "--out",
            str(out),
            "--label",
            "2026.11.28",
            "--root",
            str(ROOT),
        ]
    )
    assert code == 0
    manifest = datapack.verify_pack(out, tmp_path / "keys" / "k.pub")
    paths = {entry["path"] for entry in manifest["files"]}
    assert "mcp/asd-ism/data/releases.json" in paths
    assert all(path.startswith(("mcp/", "intel/snapshots/")) for path in paths)
