"""Live refresh status changes, failure reporting and publication boundaries."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/nightly-intel-refresh.yml"
SCRIPT = ROOT / "tools/ci/nightly_intel_refresh.py"
_SPEC = importlib.util.spec_from_file_location("nightly_intel_refresh", SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
nightly = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = nightly
_SPEC.loader.exec_module(nightly)


@pytest.fixture(autouse=True)
def github_output(monkeypatch, tmp_path):
    path = tmp_path / "github_output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(path))
    return path


def _run(root, runner, changes=lambda: [], env=None, **overrides):
    values = dict(
        sources=nightly.PUBLIC_SOURCES,
        catalogue="feeds/catalogue.yaml",
        summary="PR_BODY.md",
        env={} if env is None else env,
        runner=runner,
        changes=changes,
        root=root,
    )
    values.update(overrides)
    return nightly.execute(**values)


def _status(root, state, timestamp="2026-10-18T00:00:00Z", detail=""):
    path = root / "feeds/status.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "sources": {
                    "asd": {
                        "status": state,
                        "last_attempt": timestamp,
                        "detail": detail,
                    }
                }
            }
        )
    )


@pytest.mark.parametrize(
    "path",
    [
        "feeds/catalogue.yaml",
        "feeds/status.json",
        "PR_BODY.md",
        "mcp/asd-acsc/data/alerts.json",
        "mcp/cisa-kev/data",
        "skills/asd-acsc/references/guide.md",
    ],
)
def test_data_directories_are_allowed(path):
    assert nightly.allowed_data_path(path)


@pytest.mark.parametrize(
    "path",
    [
        "README.md",
        ".env",
        "/etc/passwd",
        "../.env",
        "intel/snapshots/a.json",
        "feeds/../../.env",
        "mcp/common/src/cyberau_common/cli.py",
        "mcp/ASD-acsc/data/x.json",
        "skills/asd-acsc/SKILL.md",
        "PR_BODY.md.txt",
        "C:/Users/public/feeds/a.json",
        ".github/workflows/ci.yml",
    ],
)
def test_paths_outside_the_data_directories_are_refused(path):
    assert not nightly.allowed_data_path(path)


def test_unsafe_output_path_is_refused_before_refresh(tmp_path, github_output):
    def runner(args):
        pytest.fail("Unsafe output must not reach refresh")

    assert _run(tmp_path, runner, summary="../.env") == 1
    assert github_output.read_text().strip() == "open_pr=false"


def test_public_refresh_passes_supported_sources_and_opens_status_pr(tmp_path, github_output):
    calls = []

    def runner(args):
        calls.append(args)
        _status(tmp_path, "ok")
        return nightly.CommandResult(0, "", "")

    assert _run(tmp_path, runner, lambda: ["feeds/status.json", "PR_BODY.md"]) == 0
    assert calls == [
        [
            "refresh",
            "--sources",
            "asd,kev,epss,auscert,feodo",
            "--catalogue",
            "feeds/catalogue.yaml",
            "--summary",
            "PR_BODY.md",
        ]
    ]
    assert github_output.read_text().strip() == "open_pr=true"


def test_timestamp_change_does_not_open_a_status_pr(tmp_path, github_output):
    _status(tmp_path, "ok")

    def runner(args):
        _status(tmp_path, "ok", timestamp="2026-10-19T00:00:00Z")
        return nightly.CommandResult(0, "", "")

    assert _run(tmp_path, runner, lambda: ["feeds/status.json", "PR_BODY.md"]) == 0
    assert github_output.read_text().strip() == "open_pr=false"


@pytest.mark.parametrize("before,after,code", [("ok", "fail", 1), ("fail", "ok", 0)])
def test_failure_and_recovery_change_status_and_preserve_exit_code(
    tmp_path,
    github_output,
    before,
    after,
    code,
):
    _status(tmp_path, before)

    def runner(args):
        _status(tmp_path, after)
        return nightly.CommandResult(code, "", "source unavailable" if code else "")

    assert _run(tmp_path, runner, lambda: ["feeds/status.json"]) == code
    assert github_output.read_text().strip() == "open_pr=true"


def test_absent_command_is_an_error(tmp_path, github_output, capsys):
    def runner(args):
        return nightly.CommandResult(2, "", nightly.ABSENT_MARKER)

    assert _run(tmp_path, runner) == 1
    assert "::error title=Intel refresh not run::" in capsys.readouterr().out
    assert github_output.read_text().strip() == "open_pr=false"


def test_bad_flags_on_existing_command_are_not_absence(tmp_path, github_output):
    def runner(args):
        return nightly.CommandResult(
            2, "", "usage: cyberau-mcp refresh [-h]\nerror: unrecognized arguments: --bad"
        )

    assert _run(tmp_path, runner) == 2
    assert github_output.read_text().strip() == "open_pr=false"


def test_outside_change_prevents_publication(tmp_path, github_output):
    def runner(args):
        _status(tmp_path, "ok")
        return nightly.CommandResult(0, "", "")

    assert _run(tmp_path, runner, lambda: ["feeds/status.json", ".env"]) == 1
    assert github_output.read_text().strip() == "open_pr=false"


def test_summary_alone_does_not_open_a_pull_request(tmp_path, github_output):
    def runner(args):
        return nightly.CommandResult(0, "", "")

    assert _run(tmp_path, runner, lambda: ["PR_BODY.md"]) == 0
    assert github_output.read_text().strip() == "open_pr=false"


def test_secret_values_are_scrubbed_from_logs_summary_and_status(tmp_path, capsys):
    secret = "fake-refresh-key-value"

    def runner(args):
        _status(tmp_path, "fail", detail=secret)
        (tmp_path / "PR_BODY.md").write_text("Upstream: " + secret)
        return nightly.CommandResult(1, secret, "Authorization: Bearer " + secret)

    assert _run(tmp_path, runner, env={"OTX_API_KEY": secret}) == 1
    captured = capsys.readouterr()
    for text in [
        captured.out,
        captured.err,
        (tmp_path / "PR_BODY.md").read_text(),
        (tmp_path / "feeds/status.json").read_text(),
    ]:
        assert secret not in text
        assert "[REDACTED]" in text


def test_porcelain_rename_checks_both_paths():
    blob = "R  feeds/new.json\0.env\0 M feeds/status.json\0"
    paths = nightly.parse_porcelain_z(blob)
    assert paths == ["feeds/new.json", ".env", "feeds/status.json"]
    assert nightly.outside_data_dirs(paths) == [".env"]


def test_git_changes_lists_files_in_a_fresh_repository(tmp_path):
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "README.md").write_text("x")
    _status(tmp_path, "ok")
    assert set(nightly.git_changes(tmp_path)) == {"README.md", "feeds/status.json"}


def test_main_propagates_absence(monkeypatch, github_output):
    monkeypatch.setattr(
        nightly,
        "run_cyberau",
        lambda args, env: nightly.CommandResult(2, "", nightly.ABSENT_MARKER),
    )
    assert nightly.main([]) == 1
    assert github_output.read_text().strip() == "open_pr=false"


def test_success_or_failure_with_absent_text_is_not_placeholder_absence():
    assert not nightly.is_absent(nightly.CommandResult(0, nightly.ABSENT_MARKER, ""))
    assert not nightly.is_absent(nightly.CommandResult(1, "", nightly.ABSENT_MARKER))


def test_workflow_pins_actions_and_only_publishes_status():
    text = WORKFLOW.read_text()
    assert "set -x" not in text
    assert "tests/snapshots --block-network" in text
    assert "--sources asd,kev,epss,auscert,feodo" in text
    assert "--optional-sources" not in text
    assert "intel/snapshots" not in text
    assert "continue-on-error: true" in text
    assert "needs.refresh.outputs.outcome == 'failure'" in text
    assert "DATA_PR_TOKEN: ${{ secrets.DATA_PR_TOKEN }}" in text
    artifact = text.split("path: |", 1)[1].split("\n  pr:", 1)[0]
    assert artifact.split() == ["feeds/status.json", "PR_BODY.md"]
    for line in text.splitlines():
        if "uses: actions/" in line:
            assert re.search(r"@[0-9a-f]{40} # v[0-9]+[.][0-9]+[.][0-9]+$", line)
