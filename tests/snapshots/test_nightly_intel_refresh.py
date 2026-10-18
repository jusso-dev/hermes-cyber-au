"""Nightly threat intel refresh: absent commands, keyed secrets, and data paths."""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "nightly-intel-refresh.yml"
SCRIPT = ROOT / "tools" / "ci" / "nightly_intel_refresh.py"

_SPEC = importlib.util.spec_from_file_location("nightly_intel_refresh", SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
nightly = importlib.util.module_from_spec(_SPEC)
sys.modules["nightly_intel_refresh"] = nightly
_SPEC.loader.exec_module(nightly)

FAKE_KEYS = {
    "NVD_API_KEY": "fake-nvd-key-value",
    "ABUSECH_AUTH_KEY": "fake-abusech-key-value",
    "OTX_API_KEY": "fake-otx-key-value",
    "CLOUDFLARE_RADAR_API_TOKEN": "fake-radar-token-value",
}

ALLOWED = [
    "intel/snapshots",
    "intel/snapshots/public-2026-10-17.sqlite.zst",
    "feeds/catalogue.yaml",
    "feeds/status.json",
    "PR_BODY.md",
    "mcp/asd-acsc/data/alerts.json",
    "mcp/cisa-kev/data",
    "skills/asd-acsc/references/guide.md",
]

REFUSED = [
    "README.md",
    ".env",
    "/etc/passwd",
    "../.env",
    "intel/snapshots/../../.env",
    "mcp/common/src/cyberau_common/cli.py",
    "mcp/ASD-acsc/data/x.json",
    "skills/asd-acsc/SKILL.md",
    "PR_BODY.md.txt",
    "intel/snapshots-extra/a.json",
    "C:/Users/public/intel/snapshots/a.json",
]


@pytest.fixture(autouse=True)
def github_output(monkeypatch, tmp_path):
    path = tmp_path / "github_output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(path))
    return path


def _absent(args):
    """What the shared library CLI returns today for refresh and store."""
    return nightly.CommandResult(2, "", f"{args[0]} {nightly.ABSENT_MARKER}")


def _env_without_keys() -> dict[str, str]:
    env = os.environ.copy()
    for name in nightly.KEYED_SECRETS.values():
        env.pop(name, None)
    return env


def _run(env, runner, changes, **overrides):
    values = {
        "sources": nightly.PUBLIC_SOURCES,
        "optional_sources": nightly.OPTIONAL_SOURCES,
        "snapshot_dir": "intel/snapshots",
        "catalogue": "feeds/catalogue.yaml",
        "summary": "PR_BODY.md",
        "env": env,
        "runner": runner,
        "changes": changes,
    }
    values.update(overrides)
    return nightly.execute(**values)


@pytest.mark.parametrize("path", ALLOWED)
def test_data_directories_are_allowed(path):
    assert nightly.allowed_data_path(path)


@pytest.mark.parametrize("path", REFUSED)
def test_paths_outside_the_data_directories_are_refused(path):
    assert not nightly.allowed_data_path(path)


def test_absent_commands_are_reported_and_outside_paths_are_refused(capsys, github_output):
    calls = []
    env = _env_without_keys()

    def spy(args):
        calls.append(list(args))
        return _absent(args)

    code = _run(
        env,
        spy,
        lambda: ["README.md", "feeds/catalogue.yaml"],
        snapshot_dir="../outside",
    )
    captured = capsys.readouterr()
    assert code == 1
    assert nightly.REFRESH_ABSENT in captured.out
    assert nightly.STORE_ABSENT in captured.out
    assert captured.err.startswith(nightly.REFUSAL_PREFIX)
    assert "../outside" in captured.err
    assert "README.md" in captured.err
    assert "feeds/catalogue.yaml" not in captured.err
    assert calls[0][0] == "refresh"
    assert "../outside" not in calls[0]
    assert calls[1] == ["store", "snapshot", "--public"]
    assert github_output.read_text(encoding="utf-8").strip() == "open_pr=false"


def test_keyed_sources_run_only_when_their_secret_exists(capsys):
    calls = []
    env = _env_without_keys()
    env["ABUSECH_AUTH_KEY"] = FAKE_KEYS["ABUSECH_AUTH_KEY"]
    env["CLOUDFLARE_RADAR_API_TOKEN"] = "   "
    env["OTX_API_KEY"] = FAKE_KEYS["OTX_API_KEY"]

    def spy(args):
        calls.append(list(args))
        return _absent(args)

    code = _run(env, spy, lambda: [])
    captured = capsys.readouterr()
    assert code == 0
    refresh = calls[0]
    assert refresh[refresh.index("--optional-sources") + 1] == "abusech,otx"
    assert "nvd" not in refresh
    assert "radar" not in refresh
    for value in FAKE_KEYS.values():
        assert value not in refresh
        assert value not in captured.out
        assert value not in captured.err
    assert nightly.REFRESH_ABSENT in captured.out
    assert nightly.STORE_ABSENT in captured.out


def test_all_keyed_sources_are_passed_when_every_secret_exists():
    calls = []
    env = _env_without_keys()
    env.update(FAKE_KEYS)

    def spy(args):
        calls.append(list(args))
        return nightly.CommandResult(2, "", nightly.ABSENT_MARKER)

    _run(env, spy, lambda: [])
    refresh = calls[0]
    assert refresh[refresh.index("--optional-sources") + 1] == "nvd,abusech,otx,radar"
    joined = " ".join(refresh)
    for value in FAKE_KEYS.values():
        assert value not in joined


def test_unknown_keyed_source_is_refused(capsys, github_output):
    def fail(args):
        raise AssertionError(args)

    code = _run(_env_without_keys(), fail, lambda: [], optional_sources="nvd,made-up")
    captured = capsys.readouterr()
    assert code == 1
    assert "Unknown keyed source: made-up" in captured.err
    assert "open_pr=false" in github_output.read_text(encoding="utf-8")


def test_present_commands_can_open_a_pull_request_for_data_paths(capsys, github_output):
    def present(args):
        return nightly.CommandResult(0, "wrote snapshots", "")

    code = _run(
        _env_without_keys(),
        present,
        lambda: [
            "intel/snapshots/public-2026-10-17.sqlite.zst",
            "feeds/catalogue.yaml",
            "PR_BODY.md",
        ],
    )
    captured = capsys.readouterr()
    assert code == 0
    assert nightly.ABSENT_MARKER not in captured.out
    assert github_output.read_text(encoding="utf-8").strip() == "open_pr=true"


def test_present_command_that_writes_outside_data_directories_is_refused(capsys):
    def present(args):
        return nightly.CommandResult(0, "", "")

    code = _run(_env_without_keys(), present, lambda: ["intel/snapshots/a.json", ".env"])
    captured = capsys.readouterr()
    assert code == 1
    assert ".env" in captured.err
    assert "intel/snapshots/a.json" not in captured.err


def test_failed_command_is_not_called_absent_and_does_not_echo_the_secret(capsys, github_output):
    secret = FAKE_KEYS["NVD_API_KEY"]

    def runner(args):
        if args[0] == "refresh":
            return nightly.CommandResult(1, "", f"Authorization: Bearer {secret}")
        return nightly.CommandResult(0, "", "")

    env = _env_without_keys()
    env["NVD_API_KEY"] = secret
    code = _run(env, runner, lambda: [], optional_sources="nvd")
    captured = capsys.readouterr()
    assert code == 1
    assert secret not in captured.out
    assert secret not in captured.err
    assert "[REDACTED]" in captured.err
    assert nightly.ABSENT_MARKER not in captured.out
    assert "open_pr=false" in github_output.read_text(encoding="utf-8")


def test_shared_library_still_says_the_commands_are_absent():
    source = (ROOT / "mcp" / "common" / "src" / "cyberau_common" / "cli.py").read_text(
        encoding="utf-8"
    )
    assert nightly.ABSENT_MARKER in source


def test_absent_is_reported_as_a_warning_annotation(capsys):
    _run(_env_without_keys(), _absent, lambda: [])
    out = capsys.readouterr().out
    assert f"::warning title=Intel refresh not run::{nightly.REFRESH_ABSENT}" in out


def test_bad_flags_on_an_existing_command_are_not_called_absent(capsys, github_output):
    def runner(args):
        return nightly.CommandResult(
            2, "", "usage: cyberau-mcp refresh [-h]\nerror: unrecognized arguments: --summary x"
        )

    code = _run(_env_without_keys(), runner, lambda: [])
    captured = capsys.readouterr()
    assert code == 2
    assert nightly.ABSENT_MARKER not in captured.out
    assert "unrecognized arguments" in captured.err
    assert "open_pr=false" in github_output.read_text(encoding="utf-8")


ROOT_PARSER_ERROR = (
    "usage: cyberau-mcp [-h]\n"
    "                   {serve,health,new,import,refresh,regen,parser-check,store}\n"
    "                   ...\n"
    "cyberau-mcp: error: unrecognized arguments: --sources asd\n"
)


def test_top_level_parser_rejection_of_the_placeholder_command_is_absence():
    assert nightly.is_absent(nightly.CommandResult(2, "", ROOT_PARSER_ERROR))
    own_parser = (
        "usage: cyberau-mcp refresh [-h]\ncyberau-mcp refresh: error: unrecognized arguments: --x"
    )
    assert not nightly.is_absent(nightly.CommandResult(2, "", own_parser))


def test_real_cli_placeholders_are_reported_as_absent(monkeypatch):
    source = (ROOT / "mcp" / "common" / "src" / "cyberau_common" / "cli.py").read_text(
        encoding="utf-8"
    )
    if 'for name in ("refresh", "regen", "parser-check", "store"):' not in source:
        pytest.skip("refresh is implemented; this check would start a live refresh")
    env = _env_without_keys()
    refresh = nightly.run_cyberau(
        nightly.refresh_args(
            nightly.PUBLIC_SOURCES,
            [],
            {
                "snapshot_dir": "intel/snapshots",
                "catalogue": "feeds/catalogue.yaml",
                "summary": "PR_BODY.md",
            },
        ),
        env,
    )
    store = nightly.run_cyberau(list(nightly.STORE_ARGS), env)
    assert nightly.is_absent(refresh)
    assert nightly.is_absent(store)


def test_absent_marker_in_output_of_a_successful_or_failed_run_is_not_absence():
    marker = nightly.ABSENT_MARKER
    assert not nightly.is_absent(nightly.CommandResult(0, marker, ""))
    assert not nightly.is_absent(nightly.CommandResult(1, "", marker))
    assert nightly.is_absent(nightly.CommandResult(2, "", f"refresh {marker}"))


def test_summary_alone_does_not_open_a_pull_request(github_output):
    def present(args):
        return nightly.CommandResult(0, "", "")

    code = _run(_env_without_keys(), present, lambda: ["PR_BODY.md"])
    assert code == 0
    assert github_output.read_text(encoding="utf-8").strip() == "open_pr=false"


def test_secret_values_are_scrubbed_from_the_pr_body(tmp_path):
    secret = FAKE_KEYS["OTX_API_KEY"]
    body = tmp_path / "PR_BODY.md"
    body.write_text(f"Refreshed.\nupstream said {secret}\n", encoding="utf-8")
    env = _env_without_keys()
    env["OTX_API_KEY"] = secret

    def present(args):
        return nightly.CommandResult(0, "", "")

    code = _run(env, present, lambda: ["PR_BODY.md", "feeds/catalogue.yaml"], root=tmp_path)
    text = body.read_text(encoding="utf-8")
    assert code == 0
    assert secret not in text
    assert "[REDACTED]" in text
    assert text.startswith("Refreshed.")


def test_porcelain_rename_uses_the_new_path():
    blob = "R  old.txt\0feeds/catalogue.yaml\0 M intel/snapshots/a.json\0?? README.md\0"
    assert nightly.parse_porcelain_z(blob) == [
        "feeds/catalogue.yaml",
        "intel/snapshots/a.json",
        "README.md",
    ]


def test_git_changes_lists_files_in_a_fresh_repository(tmp_path):
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "README.md").write_text("x\n", encoding="utf-8")
    snapshot = tmp_path / "intel" / "snapshots"
    snapshot.mkdir(parents=True)
    (snapshot / "a.json").write_text("{}\n", encoding="utf-8")
    found = set(nightly.git_changes(tmp_path))
    assert "README.md" in found
    assert "intel/snapshots/a.json" in found


def test_main_reports_absent_commands(monkeypatch, capsys, github_output):
    monkeypatch.setattr(nightly, "git_changes", lambda root: [])
    monkeypatch.setattr(nightly, "run_cyberau", lambda args, env: _absent(args))
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    monkeypatch.delenv("CLOUDFLARE_RADAR_API_TOKEN", raising=False)
    code = nightly.main(
        [
            "--sources",
            nightly.PUBLIC_SOURCES,
            "--optional-sources",
            nightly.OPTIONAL_SOURCES,
            "--snapshot-dir",
            "intel/snapshots",
            "--catalogue",
            "feeds/catalogue.yaml",
            "--summary",
            "PR_BODY.md",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert nightly.REFRESH_ABSENT in captured.out
    assert nightly.STORE_ABSENT in captured.out
    assert github_output.read_text(encoding="utf-8").strip() == "open_pr=false"
    for value in FAKE_KEYS.values():
        assert value not in captured.out
        assert value not in captured.err


def test_workflow_pins_actions_and_keeps_secrets_in_the_step_env():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "\u2014" not in text
    assert "echo " not in text
    assert "set -x" not in text
    assert "tests/snapshots" in text
    assert "--block-network" in text
    assert "tools/ci/nightly_intel_refresh.py" in text
    assert "--sources asd,kev,epss,auscert,attack,feodo" in text
    assert "--optional-sources nvd,abusech,otx,radar" in text
    assert "uses: ./.github/workflows/data-update-pr.yml" in text
    env_secret = re.compile(r"^[A-Z0-9_]+: \$\{\{ secrets\.[A-Z0-9_]+ \}\}$")
    pinned = re.compile(r"[^@\s]+@[0-9a-f]{40} # v\d+\.\d+\.\d+")
    saw_action = False
    for line in text.splitlines():
        stripped = line.strip().removeprefix("- ").strip()
        if "uses:" in stripped and "actions/" in stripped:
            saw_action = True
            assert pinned.fullmatch(stripped.split("uses:", 1)[1].strip())
        if "secrets." in line:
            assert env_secret.fullmatch(stripped)
    assert saw_action
    for source, variable in nightly.KEYED_SECRETS.items():
        assert f"{variable}: ${{{{ secrets.{variable} }}}}" in text
        assert source in text


def test_house_style_has_no_em_dash():
    for path in (WORKFLOW, SCRIPT, Path(__file__)):
        assert "\u2014" not in path.read_text(encoding="utf-8")
