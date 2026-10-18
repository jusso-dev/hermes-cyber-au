"""The dev container pins its images and keeps Codespaces secrets out of the repo."""

from __future__ import annotations

import json
import re
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEVCONTAINER = ROOT / ".devcontainer"


def test_devcontainer_json_builds_the_local_dockerfile():
    config = json.loads((DEVCONTAINER / "devcontainer.json").read_text(encoding="utf-8"))
    assert config["build"]["dockerfile"] == "Dockerfile"
    assert config["postCreateCommand"] == "sh .devcontainer/post-create.sh"
    assert config["remoteUser"] == "hermes"
    for name in config["secrets"]:
        assert re.fullmatch(r"[A-Z][A-Z0-9_]*", name)


def test_every_base_image_is_pinned_by_digest():
    froms = [
        line.split()[1]
        for line in (DEVCONTAINER / "Dockerfile").read_text(encoding="utf-8").splitlines()
        if line.startswith("FROM ")
    ]
    assert froms
    for image in froms:
        assert re.search(r":[\w.-]+@sha256:[0-9a-f]{64}$", image), image


def test_hermes_base_matches_the_distribution_pin():
    dockerfile = (DEVCONTAINER / "Dockerfile").read_text(encoding="utf-8")
    image = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
    version = re.search(r"ARG HERMES_VERSION=(v[\d.]+)", image).group(1)
    assert f"nousresearch/hermes-agent:{version}@sha256:" in dockerfile


def test_post_create_installs_keyless_from_the_checkout():
    script = (DEVCONTAINER / "post-create.sh").read_text(encoding="utf-8")
    assert "install/install.sh --no-hermes-install --non-interactive --yes" in script
    assert "cyber-au doctor --offline" in script
    assert "cyber-au demo triage" in script
    assert "set -x" not in script


def _copy(tmp_path: Path, env: dict[str, str]) -> tuple[subprocess.CompletedProcess, Path]:
    env_file = tmp_path / ".env"
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(DEVCONTAINER / "env_from_secrets.py"),
            str(ROOT / "distribution.yaml"),
            str(env_file),
        ],
        capture_output=True,
        text=True,
        check=True,
        env={"PATH": "/usr/bin:/bin", **env},
    )
    return result, env_file


def test_secrets_go_to_the_profile_env_with_mode_600_and_are_not_printed(tmp_path):
    fake = "fake-value-for-test-only"
    result, env_file = _copy(tmp_path, {"NVD_API_KEY": fake, "NOT_IN_MANIFEST": "x"})
    assert fake not in result.stdout + result.stderr
    assert "NVD_API_KEY" in result.stdout
    assert env_file.read_text(encoding="utf-8") == f"NVD_API_KEY={fake}\n"
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600


def test_no_secrets_writes_nothing(tmp_path):
    result, env_file = _copy(tmp_path, {})
    assert not env_file.exists()
    assert "public sources" in result.stdout


def test_existing_value_is_kept(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("NVD_API_KEY=already-there\n", encoding="utf-8")
    _copy(tmp_path, {"NVD_API_KEY": "new"})
    assert env_file.read_text(encoding="utf-8") == "NVD_API_KEY=already-there\n"
