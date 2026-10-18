"""Tests for tools/hermes_pin.py and the weekly bump workflow."""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / "ci" / "workflows" / "deps-and-hermes-bump.yml"
PIN_PATH = ROOT / "tools" / "hermes_pin.py"

SHA_PINS = {
    "actions/checkout": ("3d3c42e5aac5ba805825da76410c181273ba90b1", "v7.0.1"),
    "actions/setup-python": ("5fda3b95a4ea91299a34e894583c3862153e4b97", "v7.0.0"),
    "actions/upload-artifact": ("ea165f8d65b6e75b540449e92b4886f43607fa02", "v4.6.2"),
}
CARRIED = (
    "mcp/uv.lock",
    "distribution.yaml",
    "docker/Dockerfile",
    "tools/hermes_pin.txt",
    "ci/workflows/ci.yml",
    ".github/workflows/ci.yml",
    "PR_BODY.md",
)


def _load():
    spec = importlib.util.spec_from_file_location("hermes_pin", PIN_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["hermes_pin"] = module
    spec.loader.exec_module(module)
    return module


pin = _load()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _fixture(
    tmp_path: Path, *, dockerfile: bool = True, ci: bool = True, github_ci: bool = False
) -> Path:
    _write(tmp_path / "tools" / "hermes_pin.txt", "# Pinned Hermes release.\nv0.22.2\n")
    _write(
        tmp_path / "distribution.yaml", 'name: cyber-au\nhermes_requires: ">=0.22.2"\n'
    )
    if dockerfile:
        _write(
            tmp_path / "docker" / "Dockerfile",
            "ARG HERMES_VERSION=v0.22.2\nFROM nousresearch/hermes-agent:${HERMES_VERSION}\n",
        )
    if ci:
        _write(
            tmp_path / "ci" / "workflows" / "ci.yml",
            "env:\n  HERMES_IMAGE: nousresearch/hermes-agent:v0.22.2   # bumped by deps-and-hermes-bump.yml\n",
        )
    if github_ci:
        _write(
            tmp_path / ".github" / "workflows" / "ci.yml",
            "env:\n  HERMES_IMAGE: nousresearch/hermes-agent:v0.22.2   # bumped by deps-and-hermes-bump.yml\n",
        )
    return tmp_path


def test_repository_pin_is_the_current_release():
    assert pin.read_pin(ROOT) == "v0.22.2"
    distribution = (ROOT / "distribution.yaml").read_text(encoding="utf-8")
    ci = (ROOT / "ci" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert 'hermes_requires: ">=0.22.2"\n' in distribution
    assert "nousresearch/hermes-agent:v0.22.2" in ci


def test_get_prints_only_the_tag(tmp_path: Path):
    root = _fixture(tmp_path)
    result = subprocess.run(
        [sys.executable, str(PIN_PATH), "--root", str(root), "get"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert result.stdout == "v0.22.2\n"
    assert result.stderr == ""


def test_set_updates_every_consumer_and_keeps_the_comment(tmp_path: Path):
    root = _fixture(tmp_path, github_ci=True)
    real_distribution = (ROOT / "distribution.yaml").read_text(encoding="utf-8")
    real_ci = (ROOT / "ci" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    pin.set_pin(root, "v9.9.9")

    assert (ROOT / "distribution.yaml").read_text(encoding="utf-8") == real_distribution
    assert (ROOT / "ci" / "workflows" / "ci.yml").read_text(encoding="utf-8") == real_ci
    assert "v9.9.9" not in real_distribution
    assert "v9.9.9" not in real_ci

    text = (root / "tools" / "hermes_pin.txt").read_text(encoding="utf-8")
    assert text.startswith("# Pinned Hermes release.\n")
    assert text.endswith("v9.9.9\n")
    assert 'hermes_requires: ">=9.9.9"\n' in (root / "distribution.yaml").read_text(
        encoding="utf-8"
    )
    dockerfile = (root / "docker" / "Dockerfile").read_text(encoding="utf-8")
    assert "ARG HERMES_VERSION=v9.9.9\n" in dockerfile
    assert "FROM nousresearch/hermes-agent:${HERMES_VERSION}\n" in dockerfile
    for rel in ("ci/workflows/ci.yml", ".github/workflows/ci.yml"):
        updated = (root / rel).read_text(encoding="utf-8")
        assert (
            "nousresearch/hermes-agent:v9.9.9   # bumped by deps-and-hermes-bump.yml"
            in updated
        )


def test_set_is_idempotent_for_the_same_tag(tmp_path: Path):
    root = _fixture(tmp_path)
    before = {
        rel: (root / rel).read_text(encoding="utf-8")
        for rel in (
            "tools/hermes_pin.txt",
            "distribution.yaml",
            "docker/Dockerfile",
            "ci/workflows/ci.yml",
        )
    }
    pin.set_pin(root, "v0.22.2")
    after = {rel: (root / rel).read_text(encoding="utf-8") for rel in before}
    assert after == before


def test_set_accepts_the_real_distribution_and_ci_formats(tmp_path: Path):
    root = _fixture(tmp_path, dockerfile=True, ci=False)
    shutil.copy(ROOT / "distribution.yaml", root / "distribution.yaml")
    (root / "ci" / "workflows").mkdir(parents=True)
    shutil.copy(
        ROOT / "ci" / "workflows" / "ci.yml", root / "ci" / "workflows" / "ci.yml"
    )
    pin.set_pin(root, "v9.9.9")
    distribution = (root / "distribution.yaml").read_text(encoding="utf-8")
    ci = (root / "ci" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert 'hermes_requires: ">=9.9.9"\n' in distribution
    assert "name: cyber-au\n" in distribution
    assert (
        "nousresearch/hermes-agent:v9.9.9   # bumped by deps-and-hermes-bump.yml" in ci
    )
    assert (ROOT / "distribution.yaml").read_text(encoding="utf-8") != distribution


def test_set_writes_nothing_when_a_consumer_is_missing(tmp_path: Path):
    root = _fixture(tmp_path, dockerfile=False)
    before = (root / "distribution.yaml").read_text(encoding="utf-8")
    with pytest.raises(pin.PinError, match="docker/Dockerfile"):
        pin.set_pin(root, "v9.9.9")
    assert (root / "distribution.yaml").read_text(encoding="utf-8") == before
    assert (
        (root / "tools" / "hermes_pin.txt")
        .read_text(encoding="utf-8")
        .endswith("v0.22.2\n")
    )


def test_set_refuses_a_tree_with_no_ci_workflow(tmp_path: Path):
    root = _fixture(tmp_path, ci=False)
    with pytest.raises(pin.PinError, match="ci.yml"):
        pin.set_pin(root, "v9.9.9")
    assert (
        (root / "tools" / "hermes_pin.txt")
        .read_text(encoding="utf-8")
        .endswith("v0.22.2\n")
    )


@pytest.mark.parametrize(
    "tag",
    [
        "main",
        "v1.2",
        "v1.2.3-rc.1",
        "v1.2.3; rm -rf /",
        "v1.2.3\nlatest=evil",
        "ghp_supersecrettoken",
    ],
)
def test_set_refuses_unexpected_tags(tmp_path: Path, tag: str):
    root = _fixture(tmp_path)
    code = pin.main(["--root", str(root), "set", tag])
    assert code == 1
    assert (
        (root / "tools" / "hermes_pin.txt")
        .read_text(encoding="utf-8")
        .endswith("v0.22.2\n")
    )


def test_rejected_token_is_not_echoed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    root = _fixture(tmp_path)
    code = pin.main(["--root", str(root), "set", "ghp_supersecrettokenvalue"])
    assert code == 1
    error = capsys.readouterr().err
    assert "ghp_supersecrettokenvalue" not in error
    assert "[redacted]" in error


def test_workflow_pins_actions_and_carries_every_pin_file():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "\u2014" not in text
    assert "\u2013" not in text
    assert 'cron: "0 22 * * 1"' in text
    assert "tools/hermes_pin.py get" in text
    assert "tools/hermes_pin.py set" in text
    assert "tools/ci/verify_hermes_facts.py" in text
    assert "ghp_" not in text
    assert "github_pat_" not in text
    assert "secrets." not in text
    for action, (sha, version) in SHA_PINS.items():
        assert f"{action}@{sha} # {version}" in text
    for line in text.splitlines():
        if "uses:" not in line:
            continue
        if "./.github/workflows/" in line:
            continue
        assert re.search(r"@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+", line), line
    assert "include-hidden-files: true" in text
    match = re.search(r"allowed_paths: '([^']+)'", text)
    assert match is not None
    pattern = match.group(1)
    for rel in CARRIED:
        assert re.search(pattern, rel), rel
    assert re.search(pattern, "changed.txt")
    assert re.search(pattern, "SOUL.md") is None
    assert re.search(pattern, "docs/research/hermes-structure.md") is None


def test_actionlint_is_clean_when_called_workflows_are_present():
    actionlint = shutil.which("actionlint")
    if actionlint is None:
        pytest.skip("actionlint is not installed")
    work = Path(tempfile.mkdtemp())
    try:
        dest = work / ".github" / "workflows"
        dest.mkdir(parents=True)
        for name in ("deps-and-hermes-bump.yml", "ci.yml", "data-update-pr.yml"):
            source = ROOT / "ci" / "workflows" / name
            (dest / name).write_text(
                source.read_text(encoding="utf-8"), encoding="utf-8"
            )
        proc = subprocess.run(
            [actionlint, str(dest / "deps-and-hermes-bump.yml")],
            cwd=work,
            check=False,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
    finally:
        shutil.rmtree(work)


def test_no_change_guard_ignores_the_pr_body_so_a_quiet_week_exits_cleanly():
    text = (ROOT / "ci" / "workflows" / "data-update-pr.yml").read_text(
        encoding="utf-8"
    )
    # The no-change guard lives in tools/ci/data_update_pr.py, which leaves the
    # PR body out of the committable paths. tests/test_data_update_pr.py covers
    # that behaviour; here we check the workflow hands the script the body path.
    assert "BODY_FILE: ${{ inputs.body_file }}" in text
    assert 'data_update_pr.py" open' in text
    script = (ROOT / "tools" / "ci" / "data_update_pr.py").read_text(encoding="utf-8")
    assert "if path != body_rel" in script
    assert "print(NO_CHANGE)" in script
