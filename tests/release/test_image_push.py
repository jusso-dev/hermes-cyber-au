"""Run the release shell with a fake Docker CLI, including failures under bash -e."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
DIGEST = "sha256:" + "a" * 64


@pytest.fixture
def run_image_step(tmp_path: Path):
    workflow = yaml.safe_load((ROOT / ".github/workflows/weekly-release.yml").read_text())
    step = next(step for step in workflow["jobs"]["package"]["steps"] if step.get("id") == "image")
    script = step["run"]
    for expression, value in {
        "github.actor": "release-test",
        "github.repository": "example/distribution",
        "steps.ver.outputs.version": "2026.11.14",
    }.items():
        script = script.replace("${{ " + expression + " }}", value)
    docker = tmp_path / "docker"
    docker.write_text(
        "#!/bin/bash\n"
        'printf "%s\\n" "$1" >> "$DOCKER_CALLS"\n'
        'case "$1" in\n'
        '  login) cat >/dev/null; exit "${LOGIN_STATUS:-0}" ;;\n'
        '  build) exit "${BUILD_STATUS:-0}" ;;\n'
        '  push) printf "%s\\n" "$PUSH_STDOUT"; printf "%s\\n" "$PUSH_STDERR" >&2; '
        'exit "$PUSH_STATUS" ;;\n'
        "  *) exit 99 ;;\n"
        "esac\n"
    )
    docker.chmod(0o755)
    output = tmp_path / "output"
    output.touch()
    calls = tmp_path / "calls"

    def run(**overrides):
        env = {
            **os.environ,
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "GH_TOKEN": "test-placeholder",
            "GITHUB_OUTPUT": str(output),
            "DOCKER_CALLS": str(calls),
            "PUSH_STDOUT": f"2026.11.14: digest: {DIGEST} size: 1234",
            "PUSH_STDERR": "",
            "PUSH_STATUS": "0",
            **overrides,
        }
        result = subprocess.run(
            ["bash", "-e", "-c", script], env=env, capture_output=True, text=True
        )
        return result, output.read_text(), calls.read_text().splitlines()

    return run


def test_push_success_emits_registry_digest(run_image_step):
    result, output, calls = run_image_step()
    assert result.returncode == 0, result.stderr
    assert DIGEST in result.stdout
    assert output == f"digest={DIGEST}\nname=ghcr.io/example/distribution\n"
    assert calls == ["login", "build", "push"]


def test_failed_push_logs_both_streams_and_preserves_exit_status(run_image_step):
    result, output, calls = run_image_step(
        PUSH_STATUS="37", PUSH_STDERR="denied: permission_denied: write_package"
    )
    assert result.returncode == 37
    assert "denied: permission_denied: write_package" in result.stderr
    assert DIGEST in result.stderr
    assert output == ""  # Even digest-looking output cannot attest a failed push.
    assert calls == ["login", "build", "push"]


def test_push_without_digest_cannot_attest(run_image_step):
    result, output, _ = run_image_step(PUSH_STDOUT="layer: Pushed")
    assert result.returncode != 0
    assert "image push did not return a digest" in result.stderr
    assert output == ""


@pytest.mark.parametrize("stage", ["LOGIN", "BUILD"])
def test_prior_failure_never_pushes(run_image_step, stage):
    result, output, calls = run_image_step(**{f"{stage}_STATUS": "23"})
    assert result.returncode == 23
    assert "push" not in calls
    assert output == ""
