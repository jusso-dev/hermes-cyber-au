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
WORKFLOW = ROOT / ".github" / "workflows" / "deps-and-hermes-bump.yml"
PIN_PATH = ROOT / "tools" / "hermes_pin.py"

EXPECTED_ACTIONS = (
    "actions/checkout",
    "actions/setup-python",
    "actions/upload-artifact",
)
CARRIED = (
    "mcp/uv.lock",
    "distribution.yaml",
    "docker/Dockerfile",
    ".devcontainer/Dockerfile",
    "install/install.sh",
    "tools/hermes_pin.txt",
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
    _write(tmp_path / "distribution.yaml", 'name: cyber-au\nhermes_requires: ">=0.22.2"\n')
    if dockerfile:
        _write(
            tmp_path / "docker" / "Dockerfile",
            "ARG HERMES_VERSION=v0.22.2\nFROM nousresearch/hermes-agent:${HERMES_VERSION}\n",
        )
    if ci:
        _write(
            tmp_path / ".github" / "workflows" / "ci.yml",
            "env:\n  HERMES_IMAGE: nousresearch/hermes-agent:v0.22.2"
            "   # bumped by deps-and-hermes-bump.yml\n",
        )
    if github_ci:
        _write(
            tmp_path / ".github" / "workflows" / "ci.yml",
            "env:\n  HERMES_IMAGE: nousresearch/hermes-agent:v0.22.2"
            "   # bumped by deps-and-hermes-bump.yml\n",
        )
    return tmp_path


def test_repository_pins_agree():
    tag = pin.read_pin(ROOT)
    distribution = (ROOT / "distribution.yaml").read_text(encoding="utf-8")
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    docker = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
    devcontainer = (ROOT / ".devcontainer" / "Dockerfile").read_text(encoding="utf-8")
    installer = (ROOT / "install" / "install.sh").read_text(encoding="utf-8")
    assert f'hermes_requires: ">={tag[1:]}"\n' in distribution
    assert "tools/hermes_pin.py image" in ci
    assert pin.image(ROOT) == f"nousresearch/hermes-agent:{tag}"
    assert f"ARG HERMES_VERSION={tag}\n" in docker
    assert f"# HERMES_DIGEST version: {tag}\n" in docker
    assert f"nousresearch/hermes-agent:{tag}@sha256:" in devcontainer
    assert f"\nHERMES_PIN_VERSION={tag}\n" in installer
    digest = re.search(r"^ARG HERMES_DIGEST=(sha256:[0-9a-f]{64})$", docker, re.MULTILINE)
    assert digest and f"{tag}@{digest.group(1)}" in devcontainer
    pin.check_ci(ROOT)


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
    real_ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    pin.set_pin(root, "v9.9.9")

    assert (ROOT / "distribution.yaml").read_text(encoding="utf-8") == real_distribution
    assert (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8") == real_ci
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
    for rel in (".github/workflows/ci.yml",):
        updated = (root / rel).read_text(encoding="utf-8")
        assert "nousresearch/hermes-agent:v0.22.2   # bumped by deps-and-hermes-bump.yml" in updated
    assert pin.image(root) == "nousresearch/hermes-agent:v9.9.9"
    with pytest.raises(pin.PinError, match="hardcodes"):
        pin.check_ci(root)


def test_set_is_idempotent_for_the_same_tag(tmp_path: Path):
    root = _fixture(tmp_path)
    before = {
        rel: (root / rel).read_text(encoding="utf-8")
        for rel in (
            "tools/hermes_pin.txt",
            "distribution.yaml",
            "docker/Dockerfile",
            ".github/workflows/ci.yml",
        )
    }
    pin.set_pin(root, "v0.22.2")
    after = {rel: (root / rel).read_text(encoding="utf-8") for rel in before}
    assert after == before


def test_set_accepts_the_real_distribution_and_ci_formats(tmp_path: Path):
    root = _fixture(tmp_path, dockerfile=True, ci=False)
    shutil.copy(ROOT / "distribution.yaml", root / "distribution.yaml")
    (root / ".github" / "workflows").mkdir(parents=True)
    shutil.copy(
        ROOT / ".github" / "workflows" / "ci.yml", root / ".github" / "workflows" / "ci.yml"
    )
    pin.set_pin(root, "v9.9.9")
    distribution = (root / "distribution.yaml").read_text(encoding="utf-8")
    ci = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert 'hermes_requires: ">=9.9.9"\n' in distribution
    assert "name: cyber-au\n" in distribution
    assert ci == (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert pin.image(root) == "nousresearch/hermes-agent:v9.9.9"
    pin.check_ci(root)
    assert (ROOT / "distribution.yaml").read_text(encoding="utf-8") != distribution


def test_set_writes_nothing_when_a_consumer_is_missing(tmp_path: Path):
    root = _fixture(tmp_path, dockerfile=False)
    before = (root / "distribution.yaml").read_text(encoding="utf-8")
    with pytest.raises(pin.PinError, match="docker/Dockerfile"):
        pin.set_pin(root, "v9.9.9")
    assert (root / "distribution.yaml").read_text(encoding="utf-8") == before
    assert (root / "tools" / "hermes_pin.txt").read_text(encoding="utf-8").endswith("v0.22.2\n")


@pytest.mark.parametrize(
    "relative,content",
    [
        ("docker/Dockerfile", "ARG HERMES_DIGEST=sha256:" + "a" * 64 + "\n"),
        (".devcontainer/Dockerfile", "FROM example.invalid/image@sha256:" + "a" * 64 + "\n"),
        ("install/install.sh", "HERMES_PIN_COMMIT=" + "a" * 40 + "\n"),
    ],
)
def test_version_bump_cannot_leave_immutable_pins_on_old_release(tmp_path, relative, content):
    root = _fixture(tmp_path)
    target = root / relative
    _write(target, (target.read_text() if target.is_file() else "") + content)
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    with pytest.raises(pin.PinError, match="manual pin update"):
        pin.set_pin(root, "v9.9.9")
    assert {path: path.read_bytes() for path in before} == before


def test_set_does_not_need_or_create_workflow_files(tmp_path: Path):
    root = _fixture(tmp_path, ci=False)
    pin.set_pin(root, "v9.9.9")
    assert pin.image(root) == "nousresearch/hermes-agent:v9.9.9"
    assert not (root / ".github").exists()


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
    assert (root / "tools" / "hermes_pin.txt").read_text(encoding="utf-8").endswith("v0.22.2\n")


def test_rejected_token_is_not_echoed(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
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
    for action in EXPECTED_ACTIONS:
        assert re.search(rf"{re.escape(action)}@[0-9a-f]{{40}} # v[0-9]+\.[0-9]+\.[0-9]+", text), (
            action
        )
    for line in text.splitlines():
        if "uses:" not in line:
            continue
        if "./.github/workflows/" in line:
            continue
        assert re.search(r"@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+", line), line
    assert "\n            .github/workflows/ci.yml" not in text
    match = re.search(r"allowed_paths: '([^']+)'", text)
    assert match is not None
    pattern = match.group(1)
    for rel in CARRIED:
        assert re.search(pattern, rel), rel
    assert re.search(pattern, "changed.txt")
    assert re.search(pattern, ".github/workflows/ci.yml") is None
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
            source = ROOT / ".github" / "workflows" / name
            (dest / name).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
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
    text = (ROOT / ".github" / "workflows" / "data-update-pr.yml").read_text(encoding="utf-8")
    # The no-change guard lives in tools/ci/data_update_pr.py, which leaves the
    # PR body out of the committable paths. tests/test_data_update_pr.py covers
    # that behaviour; here we check the workflow hands the script the body path.
    assert "BODY_FILE: ${{ inputs.body_file }}" in text
    assert 'data_update_pr.py" open' in text
    script = (ROOT / "tools" / "ci" / "data_update_pr.py").read_text(encoding="utf-8")
    assert "if path != body_rel" in script
    assert "print(NO_CHANGE)" in script


DIGEST = "sha256:" + "b" * 64
COMMIT = "c" * 40
INSTALLER = "d" * 64


def _immutable_fixture(tmp_path: Path) -> Path:
    root = _fixture(tmp_path)
    _write(
        root / "docker" / "Dockerfile",
        "# nousresearch/hermes-agent:v0.22.2. When HERMES_VERSION changes, update\n"
        "# HERMES_DIGEST version: v0.22.2\n"
        "ARG HERMES_VERSION=v0.22.2\n"
        "ARG HERMES_DIGEST=sha256:" + "a" * 64 + "\n"
        "FROM nousresearch/hermes-agent:${HERMES_VERSION}@${HERMES_DIGEST}\n",
    )
    _write(
        root / ".devcontainer" / "Dockerfile",
        "FROM nousresearch/hermes-agent:v0.22.2@sha256:" + "a" * 64 + "\n",
    )
    _write(
        root / "install" / "install.sh",
        "# v0.22.2 tag points to, checked against this SHA-256\n"
        "HERMES_PIN_VERSION=v0.22.2\n"
        "HERMES_PIN_COMMIT=" + "a" * 40 + "\n"
        "HERMES_PIN_SHA256=" + "a" * 64 + "\n",
    )
    return root


def test_set_with_resolved_pins_moves_every_immutable_pin(tmp_path: Path):
    root = _immutable_fixture(tmp_path)
    code = pin.main(
        [
            "--root",
            str(root),
            "set",
            "v9.9.9",
            "--digest",
            DIGEST,
            "--commit",
            COMMIT,
            "--installer-sha256",
            INSTALLER,
        ]
    )
    assert code == 0
    docker = (root / "docker" / "Dockerfile").read_text()
    assert "ARG HERMES_VERSION=v9.9.9" in docker
    assert f"ARG HERMES_DIGEST={DIGEST}" in docker
    assert "# HERMES_DIGEST version: v9.9.9" in docker
    assert "# nousresearch/hermes-agent:v9.9.9. When" in docker
    assert "v0.22.2" not in docker
    dev = (root / ".devcontainer" / "Dockerfile").read_text()
    assert dev == f"FROM nousresearch/hermes-agent:v9.9.9@{DIGEST}\n"
    install = (root / "install" / "install.sh").read_text()
    assert "HERMES_PIN_VERSION=v9.9.9" in install
    assert f"HERMES_PIN_COMMIT={COMMIT}" in install
    assert f"HERMES_PIN_SHA256={INSTALLER}" in install
    assert "# v9.9.9 tag points to" in install
    assert pin.read_pin(root) == "v9.9.9"


@pytest.mark.parametrize(
    "extra",
    [
        ["--digest", DIGEST],
        ["--digest", "sha256:short", "--commit", COMMIT, "--installer-sha256", INSTALLER],
        ["--digest", DIGEST, "--commit", "main", "--installer-sha256", INSTALLER],
        ["--digest", DIGEST, "--commit", COMMIT, "--installer-sha256", "x" * 64],
    ],
)
def test_set_refuses_partial_or_malformed_immutable_pins(tmp_path: Path, extra):
    root = _immutable_fixture(tmp_path)
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    assert pin.main(["--root", str(root), "set", "v9.9.9", *extra]) == 1
    assert {path: path.read_bytes() for path in before} == before


def test_resolve_reads_commit_installer_and_digest():
    import hashlib
    import json

    calls = []

    def fake_get(url, headers=None, *, head=False):
        calls.append(url)
        if "api.github.com" in url:
            return {}, json.dumps({"sha": COMMIT}).encode()
        if "raw.githubusercontent.com" in url:
            assert COMMIT in url
            return {}, b"#!/bin/sh\n"
        if "auth.docker.io" in url:
            return {}, json.dumps({"token": "registry-token"}).encode()
        assert head
        return {"Docker-Content-Digest": DIGEST}, b""

    pins = pin.resolve("v9.9.9", get=fake_get)
    assert pins == {
        "tag": "v9.9.9",
        "digest": DIGEST,
        "commit": COMMIT,
        "installer_sha256": hashlib.sha256(b"#!/bin/sh\n").hexdigest(),
    }
    assert len(calls) == 4


def test_resolve_refuses_a_missing_digest():
    import json

    def fake_get(url, headers=None, *, head=False):
        if "api.github.com" in url:
            return {}, json.dumps({"sha": COMMIT}).encode()
        if "auth.docker.io" in url:
            return {}, json.dumps({"token": "t"}).encode()
        return {}, b"x"

    with pytest.raises(pin.PinError, match="no index digest"):
        pin.resolve("v9.9.9", get=fake_get)


def test_workflow_resolves_and_passes_every_immutable_pin():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "tools/hermes_pin.py resolve" in text
    assert "--digest" in text and "--commit" in text and "--installer-sha256" in text
    assert "include-hidden-files: true" in text
