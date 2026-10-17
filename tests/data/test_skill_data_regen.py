"""Offline checks for skill data regeneration. No live pages."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from cyberau_common.cli import main
from cyberau_common.regen import (
    PARSER_CHECK_ABSENT,
    SKIP_MESSAGES,
    parser_check_main,
    regen_main,
)

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / "ci" / "workflows" / "skill-data-regen.yml"
TOKEN = "ghp_supersecretvalue123456"

PINS = {
    "actions/checkout": ("3d3c42e5aac5ba805825da76410c181273ba90b1", "v7.0.1"),
    "actions/setup-python": ("5fda3b95a4ea91299a34e894583c3862153e4b97", "v7.0.0"),
    "actions/upload-artifact": ("ea165f8d65b6e75b540449e92b4886f43607fa02", "v4.6.2"),
    "actions/download-artifact": ("d3f86a106a0bac45b974a628896c90dbdf5c8093", "v4.3.0"),
}


def _issues():
    path = ROOT / "tools" / "ci" / "open_health_issues.py"
    spec = importlib.util.spec_from_file_location("open_health_issues", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _catalog(directory: Path, control_id: str) -> None:
    directory.mkdir(parents=True)
    payload = {"catalog": {"groups": [{"controls": [{"id": control_id}]}]}}
    (directory / "ISM_catalog.json").write_text(json.dumps(payload), encoding="utf-8")


def _ism_tree(root: Path) -> Path:
    data = root / "mcp" / "asd-ism" / "data"
    _catalog(data / "v2026.06.18", "ism-0001")
    _catalog(data / "v2026.09.4", "ism-1173")
    _catalog(data / "v2025.01.1", "ism-0002")
    releases = {
        "releases": [
            {"tag_name": "v2026.06.18", "published_at": "2026-06-18T00:00:00Z"},
            {"tag_name": "v2026.09.4", "published_at": "2026-09-03T00:00:00Z"},
            {"tag_name": "v2025.01.1", "published_at": "2025-01-01T00:00:00Z"},
        ]
    }
    (data / "releases.json").write_text(json.dumps(releases), encoding="utf-8")
    return data


def test_parser_check_is_absent(tmp_path, capsys):
    destination = tmp_path / "parser-check.json"
    assert (
        parser_check_main(
            ["--sources", "asd,auscert,e8,aureg", "--json", str(destination)]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert PARSER_CHECK_ABSENT in captured.err
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["absent"] is True
    assert payload["results"] == []
    assert payload["sources"] == ["asd", "auscert", "e8", "aureg"]
    assert TOKEN not in captured.out + captured.err


def test_cli_regen_forwards_flags(capsys):
    assert main(["regen", "sigma", "--force"]) == 0
    assert SKIP_MESSAGES["sigma"] in capsys.readouterr().out


def test_cli_parser_check_is_absent(tmp_path, capsys):
    destination = tmp_path / "parser-check.json"
    assert main(["parser-check", "--json", str(destination)]) == 2
    assert PARSER_CHECK_ABSENT in capsys.readouterr().err
    assert json.loads(destination.read_text(encoding="utf-8"))["absent"] is True


def test_missing_sources_are_skipped(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN)
    monkeypatch.setenv("GH_TOKEN", TOKEN)
    for source in ("e8", "aureg", "attack", "sigma"):
        assert regen_main([source], root=tmp_path) == 0
        assert SKIP_MESSAGES[source] in capsys.readouterr().out
        assert not (tmp_path / "mcp" / source).exists()
    assert regen_main(["ism"], root=tmp_path) == 0
    assert SKIP_MESSAGES["ism"] in capsys.readouterr().out


def test_shipped_checkout_keeps_its_ism_data():
    assert (ROOT / "mcp" / "asd-ism" / "data").is_dir()


def test_ism_keeps_two_local_releases_without_a_network(tmp_path, capsys):
    data = _ism_tree(tmp_path)
    assert regen_main(["ism", "--keep", "2"], root=tmp_path) == 0
    message = capsys.readouterr().out
    assert (
        "Regenerated ISM data in mcp/asd-ism/data (kept v2026.09.4, v2026.06.18)."
        in message
    )
    assert (data / "v2026.09.4" / "ISM_catalog.json").is_file()
    assert (data / "v2026.06.18" / "ISM_catalog.json").is_file()
    assert not (data / "v2025.01.1").exists()
    assert (data / "releases.json").is_file()
    manifest = json.loads((data / "regen.json").read_text(encoding="utf-8"))
    assert manifest["live_fetch"] is False
    assert manifest["kept"] == ["v2026.09.4", "v2026.06.18"]
    assert manifest["catalogues"]["v2026.09.4"]["controls"] == 1
    assert "http" not in json.dumps(manifest)

    assert regen_main(["ism", "--keep", "2"], root=tmp_path) == 0
    assert "ISM data is unchanged." in capsys.readouterr().out
    assert regen_main(["ism", "--keep", "2", "--force"], root=tmp_path) == 0
    assert "Regenerated ISM data" in capsys.readouterr().out


def test_prefers_ticket_ism_path_when_both_exist(tmp_path, capsys):
    ticket = tmp_path / "mcp" / "ism" / "data"
    other = tmp_path / "mcp" / "asd-ism" / "data"
    _catalog(ticket / "v2026.09.4", "ism-1173")
    _catalog(other / "v2026.06.18", "ism-0001")
    assert regen_main(["ism", "--keep", "2"], root=tmp_path) == 0
    assert "mcp/ism/data" in capsys.readouterr().out
    assert (ticket / "regen.json").is_file()
    assert not (other / "regen.json").exists()


def test_published_date_wins_over_version_name(tmp_path):
    data = tmp_path / "mcp" / "asd-ism" / "data"
    _catalog(data / "v2026.09.4", "ism-1173")
    _catalog(data / "v2020.01.1", "ism-0001")
    releases = {
        "releases": [
            {"tag_name": "v2026.09.4", "published_at": "2020-01-01T00:00:00Z"},
            {"tag_name": "v2020.01.1", "published_at": "2026-12-01T00:00:00Z"},
        ]
    }
    (data / "releases.json").write_text(json.dumps(releases), encoding="utf-8")
    assert regen_main(["ism", "--keep", "1"], root=tmp_path) == 0
    manifest = json.loads((data / "regen.json").read_text(encoding="utf-8"))
    assert manifest["kept"] == ["v2020.01.1"]
    assert not (data / "v2026.09.4").exists()


def test_e8_regen_hashes_local_files(tmp_path, capsys):
    data = tmp_path / "mcp" / "e8" / "data"
    data.mkdir(parents=True)
    (data / "baseline.txt").write_text("maturity\n", encoding="utf-8")
    assert regen_main(["e8"], root=tmp_path) == 0
    assert "Regenerated Essential Eight data in mcp/e8/data." in capsys.readouterr().out
    manifest = json.loads((data / "regen.json").read_text(encoding="utf-8"))
    assert manifest["live_fetch"] is False
    assert manifest["files"][0]["path"] == "mcp/e8/data/baseline.txt"
    assert regen_main(["e8"], root=tmp_path) == 0
    assert "Essential Eight data is unchanged." in capsys.readouterr().out


def test_unknown_source_and_bad_keep(tmp_path, capsys):
    assert regen_main(["nope"], root=tmp_path) == 2
    assert "regen does not know nope." in capsys.readouterr().err
    assert regen_main(["ism", "--keep", "0"], root=tmp_path) == 2


def test_empty_ism_directory_fails(tmp_path, capsys):
    (tmp_path / "mcp" / "asd-ism" / "data").mkdir(parents=True)
    assert regen_main(["ism"], root=tmp_path) == 1
    assert "no catalogues" in capsys.readouterr().err


def test_shipped_ism_has_two_catalogues():
    data = ROOT / "mcp" / "asd-ism" / "data"
    releases = [
        path for path in data.iterdir() if (path / "ISM_catalog.json").is_file()
    ]
    assert len(releases) == 2


def test_regen_module_does_not_fetch():
    text = (ROOT / "mcp" / "common" / "src" / "cyberau_common" / "regen.py").read_text(
        encoding="utf-8"
    )
    for banned in ("httpx", "urlopen", "requests", "socket", "curl", "wget"):
        assert banned not in text


def test_workflow_skips_missing_sources_and_pins_actions():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "\u2014" not in text
    assert "\u2013" not in text
    for message in SKIP_MESSAGES.values():
        assert message in text
    assert PARSER_CHECK_ABSENT in text
    assert "tools/ci/open_health_issues.py is absent. Not opening an issue." in text
    assert "tools/build_skill_references.py --write PR_BODY.md" in text
    assert (
        "uv run --project mcp pytest -q tests/skills tests/data --block-network" in text
    )
    assert (
        "cyberau-mcp parser-check --sources asd,auscert,e8,aureg --json parser-check.json"
        in text
    )
    assert not (ROOT / ".github" / "workflows" / "skill-data-regen.yml").exists()
    assert text.count("${{ github.token }}") == 1
    assert "GH_TOKEN: ${{ github.token }}" in text
    for banned in (
        "ghp_",
        "github_pat_",
        "AKIA",
        "curl ",
        "wget ",
        "api.github.com",
        "cyber.gov.au",
    ):
        assert banned not in text
    pinned = re.findall(
        r"uses: (actions/[\w.-]+)@([0-9a-f]{40}) # (v\d+\.\d+\.\d+)", text
    )
    assert pinned
    for action, sha, version in pinned:
        expect_sha, expect_version = PINS[action]
        assert sha == expect_sha
        assert version == expect_version
    assert not re.search(r"uses: actions/[\w.-]+@v\d+", text)
    assert "./.github/workflows/data-update-pr.yml" in text
    assert "secrets: inherit" not in text
    assert "DATA_PR_TOKEN: ${{ secrets.DATA_PR_TOKEN }}" in text
    document = yaml.safe_load(text)
    assert document["permissions"] == {"contents": "read"}
    assert document["jobs"]["parser-issue"]["permissions"]["issues"] == "write"


def test_actionlint_on_the_copied_layout():
    binary = shutil.which("actionlint")
    if binary is None:
        pytest.skip("actionlint is absent")
    destination = Path("/tmp") / "skill-data-regen-actionlint"
    workflow_dir = destination / ".github" / "workflows"
    if destination.exists():
        shutil.rmtree(destination)
    workflow_dir.mkdir(parents=True)
    shutil.copy(WORKFLOW, workflow_dir / "skill-data-regen.yml")
    shutil.copy(
        ROOT / "ci" / "workflows" / "data-update-pr.yml",
        workflow_dir / "data-update-pr.yml",
    )
    completed = subprocess.run(
        [binary, str(workflow_dir / "skill-data-regen.yml")],
        check=False,
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


class _FakeGh:
    def __init__(self, issues=None):
        self.issues = list(issues or [])
        self.calls = []

    def __call__(self, args, input_text=None):
        self.calls.append(args)
        if args[:2] == ["issue", "list"]:
            return json.dumps(
                [{"number": number, "title": title} for number, title in self.issues]
            )
        if args[:2] == ["issue", "create"]:
            title = args[args.index("--title") + 1]
            self.issues.append((len(self.issues) + 1, title))
            return "created\n"
        if args[:2] == ["issue", "comment"]:
            return ""
        raise AssertionError(args)


def test_failing_parser_opens_an_issue_only_when_the_script_exists(
    tmp_path, monkeypatch
):
    module = _issues()
    payload = [
        {"source": "asd", "ok": True, "detail": "fine"},
        {"source": "auscert", "ok": False, "detail": f"selector missing {TOKEN}"},
    ]
    path = tmp_path / "parser-check.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("GH_TOKEN", TOKEN)
    hidden = _FakeGh()
    assert (
        module.main(
            ["--kind", "parser", "--input", str(path)], root=tmp_path, runner=hidden
        )
        == 0
    )
    assert hidden.calls == []

    present = _FakeGh()
    assert (
        module.main(
            ["--kind", "parser", "--input", str(path)], root=ROOT, runner=present
        )
        == 0
    )
    created = [call for call in present.calls if call[:2] == ["issue", "create"]]
    assert len(created) == 1
    assert "Parser check: auscert failing" in created[0]
    body = created[0][created[0].index("--body") + 1]
    assert TOKEN not in body
    assert "[REDACTED]" in body
    assert "untrusted data" in body
    for label in ("type:task", "area:skills", "area:ci", "priority:p1"):
        assert label in created[0]

    again = _FakeGh(issues=[(7, "Parser check: auscert failing")])
    assert (
        module.main(["--kind", "parser", "--input", str(path)], root=ROOT, runner=again)
        == 0
    )
    assert any(call[:2] == ["issue", "comment"] for call in again.calls)
    assert not any(call[:2] == ["issue", "create"] for call in again.calls)


def test_absent_parser_check_does_not_open_an_issue(tmp_path, capsys):
    module = _issues()
    path = tmp_path / "parser-check.json"
    path.write_text(
        json.dumps({"absent": True, "detail": PARSER_CHECK_ABSENT, "results": []}),
        encoding="utf-8",
    )
    runner = _FakeGh()
    assert (
        module.main(
            ["--kind", "parser", "--input", str(path)], root=ROOT, runner=runner
        )
        == 0
    )
    assert runner.calls == []
    assert PARSER_CHECK_ABSENT in capsys.readouterr().out


def test_issue_script_refuses_a_missing_token(monkeypatch):
    module = _issues()
    monkeypatch.delenv("GH_TOKEN", raising=False)
    with pytest.raises(SystemExit, match="GH_TOKEN is not set"):
        module.default_runner(["issue", "list"])


def test_issue_script_entrypoint_says_when_path_is_absent(tmp_path):
    payload = tmp_path / "parser-check.json"
    payload.write_text(json.dumps([{"source": "asd", "ok": False}]), encoding="utf-8")
    env = os.environ.copy()
    env["GH_TOKEN"] = TOKEN
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "ci" / "open_health_issues.py"),
            "--kind",
            "parser",
            "--input",
            str(payload),
        ],
        check=False,
        cwd=tmp_path,
        text=True,
        capture_output=True,
        env=env,
    )
    assert completed.returncode == 0
    assert (
        "tools/ci/open_health_issues.py is absent. Not opening an issue."
        in completed.stdout
    )
    assert TOKEN not in completed.stdout + completed.stderr


def _parser_step() -> str:
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    for step in document["jobs"]["regen"]["steps"]:
        if step.get("id") == "parsers":
            return step["run"]
    raise AssertionError("parsers step is missing")


def _run_parser_step(tmp_path, stderr, exit_code, payload):
    """Run the workflow step with a stand-in for uv. Nothing is fetched."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "uv"
    write = ""
    if payload is not None:
        write = f"printf '%s' '{json.dumps(payload)}' > parser-check.json\n"
    fake.write_text(
        f"#!/bin/sh\n{write}echo '{stderr}' >&2\nexit {exit_code}\n", encoding="utf-8"
    )
    fake.chmod(0o755)
    work = tmp_path / "work"
    work.mkdir()
    output = tmp_path / "github_output"
    output.write_text("", encoding="utf-8")
    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    env["GITHUB_OUTPUT"] = str(output)
    completed = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", _parser_step()],
        check=False,
        cwd=work,
        text=True,
        capture_output=True,
        env=env,
    )
    return completed, output.read_text(encoding="utf-8"), work


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is absent")
@pytest.mark.parametrize(
    ("stderr", "code", "payload"),
    [
        (PARSER_CHECK_ABSENT, 2, {"absent": True, "results": []}),
        ("parser-check is not part of the shared library yet", 2, None),
    ],
)
def test_parser_step_treats_an_absent_command_as_zero_failures(
    tmp_path, stderr, code, payload
):
    completed, output, work = _run_parser_step(tmp_path, stderr, code, payload)
    assert completed.returncode == 0, completed.stderr
    assert "failures=0" in output
    assert PARSER_CHECK_ABSENT in completed.stdout
    assert json.loads((work / "parser-check.json").read_text(encoding="utf-8"))["absent"]


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is absent")
def test_parser_step_does_not_mistake_a_usage_error_for_absence(tmp_path):
    completed, output, _work = _run_parser_step(
        tmp_path, "cyberau-mcp: error: unrecognized arguments: --bogus", 2, None
    )
    assert completed.returncode == 1
    assert "failures=" not in output


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is absent")
@pytest.mark.parametrize(
    "payload",
    [
        [{"source": "asd", "ok": True}, {"source": "auscert", "ok": False}],
        {"results": [{"source": "asd", "ok": True}, {"source": "auscert", "ok": False}]},
    ],
)
def test_parser_step_counts_failures_even_when_the_command_exits_nonzero(
    tmp_path, payload
):
    completed, output, _work = _run_parser_step(tmp_path, "auscert failed", 1, payload)
    assert completed.returncode == 0, completed.stderr
    assert "failures=1" in output
