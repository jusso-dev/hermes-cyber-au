"""Tests for the reusable data-update pull request workflow.

The workflow refuses paths outside the data directories, commits to a dated
branch and opens or updates one pull request. It never pushes to main.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "ci" / "data_update_pr.py"
WORKFLOW = ROOT / "ci" / "workflows" / "data-update-pr.yml"
SECRET = "super-secret-value"

_spec = importlib.util.spec_from_file_location("data_update_pr", SCRIPT)
assert _spec is not None and _spec.loader is not None
data_update_pr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(data_update_pr)

FAKE_GH = """
import json
import os
import sys
from pathlib import Path

log = Path(os.environ["GH_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(sys.argv[1:]) + "\\n")
if os.environ.get("GH_FAKE_LEAK") == "1":
    print(os.environ.get("GH_TOKEN", ""), file=sys.stderr)
    raise SystemExit(1)
command = sys.argv[1:3]
if command == ["pr", "list"]:
    existing = Path(os.environ["GH_EXISTING"])
    if existing.exists():
        sys.stdout.write(existing.read_text(encoding="utf-8"))
    raise SystemExit(0)
if command in (["pr", "create"], ["pr", "edit"]):
    raise SystemExit(0)
print("unexpected gh invocation", file=sys.stderr)
raise SystemExit(1)
"""

DEPS_ALLOWED = (
    r"^(mcp/uv\.lock|distribution\.yaml|docker/Dockerfile|"
    r"tools/hermes_pin\.txt|PR_BODY\.md)$"
)


def test_porcelain_parses_renames_and_spaces():
    blob = (
        "R  feeds/b.yaml\0feeds/a.yaml\0"
        "?? mcp/cisa-kev/data/my file.json\0"
        " M feeds/catalogue.yaml\0"
    )
    assert data_update_pr.parse_porcelain_z(blob) == [
        "feeds/b.yaml",
        "feeds/a.yaml",
        "mcp/cisa-kev/data/my file.json",
        "feeds/catalogue.yaml",
    ]


def test_default_allowed_paths():
    pattern = data_update_pr.compile_allowed(data_update_pr.DEFAULT_ALLOWED)
    allowed = [
        "mcp/cisa-kev/data/kev.json",
        "mcp/cisa-kev/data/my file.json",
        "feeds/catalogue.yaml",
        "intel/snapshots/kev.json",
        "skills/incident-triage/references/notes.md",
        "PR_BODY.md",
    ]
    refused = [
        "README.md",
        "skills/incident-triage/SKILL.md",
        "skills/Incident/references/notes.md",
        "mcp/cisa_kev/data/kev.json",
        "intel/other.json",
        "subdir/PR_BODY.md",
        ".github/workflows/data-update-pr.yml",
        ".git/hooks/pre-commit",
    ]
    assert [
        path for path in allowed if not data_update_pr.is_allowed(path, pattern)
    ] == []
    assert [path for path in refused if data_update_pr.is_allowed(path, pattern)] == []


def test_hard_deny_git_metadata_even_when_the_pattern_is_broad():
    pattern = data_update_pr.compile_allowed(".*")
    assert data_update_pr.is_allowed("feeds/catalogue.yaml", pattern)
    assert not data_update_pr.is_allowed(".git/hooks/pre-commit", pattern)
    assert not data_update_pr.is_allowed(".github/workflows/evil.yml", pattern)
    assert not data_update_pr.is_allowed("../README.md", pattern)


def test_sydney_date_and_branch_name(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("DATA_PR_DATE", raising=False)
    june = datetime(2026, 6, 15, 18, 30, tzinfo=ZoneInfo("UTC"))
    assert data_update_pr.today_sydney(now=lambda: june) == "2026-06-16"
    monkeypatch.setenv("DATA_PR_DATE", "2026-10-17")
    assert data_update_pr.today_sydney(now=lambda: june) == "2026-10-17"
    assert data_update_pr.dated_branch("data/intel-refresh", "2026-10-17") == (
        "data/intel-refresh/2026-10-17"
    )
    with pytest.raises(data_update_pr.DataPrError):
        data_update_pr.dated_branch("data/../main", "2026-10-17")
    with pytest.raises(data_update_pr.DataPrError):
        data_update_pr.dated_branch("refs/heads/main", "2026-10-17")
    monkeypatch.setenv("DATA_PR_DATE", "2026-02-31")
    with pytest.raises(data_update_pr.DataPrError):
        data_update_pr.today_sydney()


def test_push_refspec_rejects_the_default_branch():
    spec = data_update_pr.push_refspec("data/intel-refresh/2026-10-17")
    assert spec == (
        "refs/heads/data/intel-refresh/2026-10-17:refs/heads/data/intel-refresh/2026-10-17"
    )
    for branch in ("main", "master", "main/2026-10-17", "master/2026-10-17"):
        with pytest.raises(data_update_pr.DataPrError, match="default branch"):
            data_update_pr.push_refspec(branch)


def test_redact_hides_the_token():
    assert (
        data_update_pr.redact(f"token {SECRET} end", SECRET) == "token [redacted] end"
    )
    assert data_update_pr.redact("main is fine", "main") == "main is fine"


def test_empty_allowed_paths_fail_closed():
    with pytest.raises(data_update_pr.DataPrError, match="empty"):
        data_update_pr.compile_allowed("")
    with pytest.raises(data_update_pr.DataPrError, match="regular expression"):
        data_update_pr.compile_allowed("(")


def test_refuse_rejects_paths_outside_the_data_directories(tmp_path: Path):
    work, _bare, env = _repo(tmp_path)
    _plant_hooks(work, tmp_path)
    (work / "README.md").write_text("changed\n", encoding="utf-8")
    (work / "tools").mkdir()
    (work / "tools" / "note.txt").write_text("nope\n", encoding="utf-8")
    (work / "feeds" / "catalogue.yaml").write_text("new\n", encoding="utf-8")
    main_sha = _rev(work, "main", env)
    refused = _run(work, env, "refuse")
    opened = _run(work, env, "open")
    assert refused.returncode == 1
    assert opened.returncode == 1
    for result in (refused, opened):
        assert "README.md" in result.stderr
        assert "tools/note.txt" in result.stderr
        assert data_update_pr.REFUSE in result.stderr
        assert result.stdout == ""
    assert _rev(work, "main", env) == main_sha
    assert _remote_heads(work, env) == {"main"}
    assert _current_branch(work, env) == "main"
    assert not (tmp_path / "hook-ran").exists()


def test_open_commits_a_dated_branch_and_opens_one_pull_request(tmp_path: Path):
    work, bare, env = _repo(tmp_path)
    log = _install_gh(tmp_path, env)
    _plant_hooks(work, tmp_path)
    env["GIT_AUTHOR_NAME"] = "Not The Bot"
    env["GIT_AUTHOR_EMAIL"] = "not-the-bot@example.com"
    env["TITLE"] = 'Refresh "snapshots" for $DATE'
    main_sha = _rev(work, "main", env)
    (work / "feeds" / "catalogue.yaml").write_text("new\n", encoding="utf-8")
    (work / "mcp" / "cisa-kev" / "data" / "my file.json").write_text(
        "{}\n", encoding="utf-8"
    )
    (work / "PR_BODY.md").write_text("Body for the pull request.\n", encoding="utf-8")
    result = _run(work, env, "open")
    assert result.returncode == 0, result.stderr
    assert "Pushing refs/heads/data/intel-refresh/2026-10-17." in result.stdout
    assert "Pushing refs/heads/main." not in result.stdout
    assert "Opened a pull request." in result.stdout
    assert _rev(bare, "main", env) == main_sha
    assert _rev(bare, "refs/heads/data/intel-refresh/2026-10-17", env) != main_sha
    assert _rev(work, "HEAD^", env) == main_sha
    author = _git(work, env, "log", "-1", "--format=%an%n%ae%n%s").stdout.splitlines()
    assert author == [
        "cyber-au data bot",
        "41898282+github-actions[bot]@users.noreply.github.com",
        'Refresh "snapshots" for $DATE',
    ]
    files = set(
        _git(work, env, "ls-tree", "-r", "--name-only", "HEAD").stdout.splitlines()
    )
    assert "feeds/catalogue.yaml" in files
    assert "mcp/cisa-kev/data/my file.json" in files
    assert "PR_BODY.md" not in files
    assert _git(bare, env, "show", "main:feeds/catalogue.yaml").stdout == "old\n"
    calls = _gh_calls(log)
    assert calls[0][:3] == ["pr", "list", "--head"]
    assert calls[1] == [
        "pr",
        "create",
        "--base",
        "main",
        "--head",
        "data/intel-refresh/2026-10-17",
        "--title",
        'Refresh "snapshots" for $DATE',
        "--body-file",
        "PR_BODY.md",
        "--label",
        "type:task",
        "--label",
        "area:ci",
    ]
    assert SECRET not in log.read_text(encoding="utf-8")
    assert not (tmp_path / "hook-ran").exists()


def test_second_run_updates_the_existing_pull_request(tmp_path: Path):
    work, bare, env = _repo(tmp_path)
    log = _install_gh(tmp_path, env)
    main_sha = _rev(work, "main", env)
    (work / "feeds" / "catalogue.yaml").write_text("new\n", encoding="utf-8")
    (work / "PR_BODY.md").write_text("first body\n", encoding="utf-8")
    first = _run(work, env, "open")
    assert first.returncode == 0, first.stderr
    first_tip = _rev(bare, "refs/heads/data/intel-refresh/2026-10-17", env)
    _git(work, env, "checkout", "-q", "main")
    (work / "feeds" / "catalogue.yaml").write_text("newer\n", encoding="utf-8")
    (work / "PR_BODY.md").write_text("second body\n", encoding="utf-8")
    (tmp_path / "gh-existing.txt").write_text("42\n", encoding="utf-8")
    second = _run(work, env, "open")
    assert second.returncode == 0, second.stderr
    assert "Updated pull request 42." in second.stdout
    assert _rev(bare, "main", env) == main_sha
    second_tip = _rev(bare, "refs/heads/data/intel-refresh/2026-10-17", env)
    assert second_tip != first_tip
    assert (
        _git(bare, env, "show", f"{second_tip}:feeds/catalogue.yaml").stdout
        == "newer\n"
    )
    edit = _gh_calls(log)[-1]
    assert edit == ["pr", "edit", "42", "--body-file", "PR_BODY.md"]
    assert "--label" not in edit
    assert _remote_heads(work, env) == {"main", "data/intel-refresh/2026-10-17"}


def test_no_change_does_not_open_a_pull_request(tmp_path: Path):
    work, _bare, env = _repo(tmp_path)
    log = _install_gh(tmp_path, env)
    env.pop("GH_TOKEN")
    main_sha = _rev(work, "main", env)
    result = _run(work, env, "open")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == data_update_pr.NO_CHANGE
    assert _gh_calls(log) == []
    assert _rev(work, "main", env) == main_sha
    assert _remote_heads(work, env) == {"main"}


def test_body_file_alone_is_not_a_commit(tmp_path: Path):
    work, _bare, env = _repo(tmp_path)
    log = _install_gh(tmp_path, env)
    (work / "PR_BODY.md").write_text("only the body\n", encoding="utf-8")
    result = _run(work, env, "open")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == data_update_pr.NO_CHANGE
    assert _gh_calls(log) == []
    assert (
        "PR_BODY.md"
        not in _git(work, env, "ls-tree", "-r", "--name-only", "HEAD").stdout
    )


def test_deleted_data_file_is_committed(tmp_path: Path):
    work, bare, env = _repo(tmp_path)
    _install_gh(tmp_path, env)
    (work / "feeds" / "old.yaml").write_text("gone\n", encoding="utf-8")
    _commit_all(work, env, "Add a feed file")
    _git(work, env, "push", "-q", "origin", "main")
    main_sha = _rev(work, "main", env)
    (work / "feeds" / "old.yaml").unlink()
    (work / "PR_BODY.md").write_text("removed an old feed\n", encoding="utf-8")
    result = _run(work, env, "open")
    assert result.returncode == 0, result.stderr
    tip = _rev(bare, "refs/heads/data/intel-refresh/2026-10-17", env)
    listed = _git(bare, env, "ls-tree", "-r", "--name-only", tip).stdout
    assert "feeds/old.yaml" not in listed
    assert (
        "feeds/old.yaml"
        in _git(bare, env, "ls-tree", "-r", "--name-only", "main").stdout
    )
    assert _rev(bare, "main", env) == main_sha


def test_rename_out_of_a_data_directory_is_refused(tmp_path: Path):
    work, bare, env = _repo(tmp_path)
    _install_gh(tmp_path, env)
    main_sha = _rev(bare, "main", env)
    (work / "feeds" / "catalogue.yaml").rename(work / "README-new.md")
    (work / "PR_BODY.md").write_text("moved\n", encoding="utf-8")
    result = _run(work, env, "open")
    assert result.returncode == 1
    assert "README-new.md" in result.stderr
    assert data_update_pr.REFUSE in result.stderr
    assert _rev(bare, "main", env) == main_sha
    assert _remote_heads(work, env) == {"main"}


def test_symlink_inside_a_data_directory_is_refused(tmp_path: Path):
    work, bare, env = _repo(tmp_path)
    _install_gh(tmp_path, env)
    main_sha = _rev(bare, "main", env)
    (work / "feeds" / "link").symlink_to("../.github")
    (work / "PR_BODY.md").write_text("body\n", encoding="utf-8")
    refused = _run(work, env, "refuse")
    opened = _run(work, env, "open")
    for result in (refused, opened):
        assert result.returncode == 1
        assert "feeds/link" in result.stderr
        assert data_update_pr.REFUSE in result.stderr
    assert _rev(bare, "main", env) == main_sha
    assert _remote_heads(work, env) == {"main"}


@pytest.mark.parametrize("spelling", ["feeds//body.md", "feeds/./body.md", "./feeds/body.md"])
def test_body_file_is_never_committed_under_any_spelling(
    tmp_path: Path, spelling: str
):
    work, _bare, env = _repo(tmp_path)
    _install_gh(tmp_path, env)
    env["BODY_FILE"] = spelling
    (work / "feeds" / "body.md").write_text("body\n", encoding="utf-8")
    (work / "feeds" / "catalogue.yaml").write_text("new\n", encoding="utf-8")
    result = _run(work, env, "open")
    assert result.returncode == 0, result.stderr
    files = _git(work, env, "ls-tree", "-r", "--name-only", "HEAD").stdout
    assert "feeds/body.md" not in files
    assert "feeds/catalogue.yaml" in files


def test_caller_allowed_paths_override(tmp_path: Path):
    work, bare, env = _repo(tmp_path)
    _install_gh(tmp_path, env)
    env["ALLOWED_PATHS"] = DEPS_ALLOWED
    env["BRANCH_PREFIX"] = "deps/weekly"
    env["TITLE"] = "Weekly dependency and Hermes bump"
    (work / "mcp" / "uv.lock").write_text("lock\n", encoding="utf-8")
    (work / "feeds" / "catalogue.yaml").write_text("new\n", encoding="utf-8")
    (work / "PR_BODY.md").write_text("deps\n", encoding="utf-8")
    main_sha = _rev(bare, "main", env)
    refused = _run(work, env, "open")
    assert refused.returncode == 1
    assert "feeds/catalogue.yaml" in refused.stderr
    assert _remote_heads(work, env) == {"main"}
    _git(work, env, "checkout", "-q", "--", "feeds/catalogue.yaml")
    opened = _run(work, env, "open")
    assert opened.returncode == 0, opened.stderr
    assert "Pushing refs/heads/deps/weekly/2026-10-17." in opened.stdout
    assert _rev(bare, "main", env) == main_sha
    tip = "refs/heads/deps/weekly/2026-10-17"
    assert _git(bare, env, "show", f"{tip}:mcp/uv.lock").stdout == "lock\n"


def test_prefix_main_does_not_push_main(tmp_path: Path):
    work, bare, env = _repo(tmp_path)
    _install_gh(tmp_path, env)
    env["BRANCH_PREFIX"] = "main"
    main_sha = _rev(bare, "main", env)
    (work / "feeds" / "catalogue.yaml").write_text("new\n", encoding="utf-8")
    (work / "PR_BODY.md").write_text("body\n", encoding="utf-8")
    result = _run(work, env, "open")
    assert result.returncode == 1
    assert "default branch" in result.stderr
    assert "Pushing " not in result.stdout
    assert _rev(bare, "main", env) == main_sha
    assert _remote_heads(work, env) == {"main"}
    assert _current_branch(work, env) == "main"


def test_gh_failure_does_not_echo_the_token(tmp_path: Path):
    work, bare, env = _repo(tmp_path)
    _install_gh(tmp_path, env, leak=True)
    main_sha = _rev(bare, "main", env)
    (work / "feeds" / "catalogue.yaml").write_text("new\n", encoding="utf-8")
    (work / "PR_BODY.md").write_text("body\n", encoding="utf-8")
    result = _run(work, env, "open")
    assert result.returncode == 1
    assert "[redacted]" in result.stderr
    assert SECRET not in result.stdout + result.stderr
    assert _rev(bare, "main", env) == main_sha


def test_missing_token_does_not_push(tmp_path: Path):
    work, bare, env = _repo(tmp_path)
    _install_gh(tmp_path, env)
    env.pop("GH_TOKEN")
    main_sha = _rev(bare, "main", env)
    (work / "feeds" / "catalogue.yaml").write_text("new\n", encoding="utf-8")
    (work / "PR_BODY.md").write_text("body\n", encoding="utf-8")
    result = _run(work, env, "open")
    assert result.returncode == 1
    assert "GH_TOKEN is not set." in result.stderr
    assert _rev(bare, "main", env) == main_sha
    assert _remote_heads(work, env) == {"main"}


def test_script_usage():
    assert data_update_pr.main([]) == 2


def test_workflow_is_pinned_and_leaves_github_workflows_for_justin():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "Justin copies this file into .github/workflows/ by hand." in text
    assert "It never pushes to main." in text
    assert "echo " not in text
    assert "ghp_" not in text
    assert "github_pat_" not in text
    assert "git push" not in text
    assert "python3 tools/ci/data_update_pr.py" not in text
    assert SCRIPT.is_file()
    copy_at = text.index("cp tools/ci/data_update_pr.py")
    download_at = text.index("actions/download-artifact@")
    refuse_at = text.index('data_update_pr.py" refuse')
    open_at = text.index('data_update_pr.py" open')
    assert copy_at < download_at < refuse_at < open_at
    uses = [line for line in text.splitlines() if "uses:" in line]
    assert uses
    for line in uses:
        assert re.search(r"@[0-9a-f]{40} # v\d+\.\d+\.\d+\s*$", line), line
    default = _workflow_default_allowed(text)
    assert default == data_update_pr.DEFAULT_ALLOWED
    refuse = text.split("- name: Refuse unexpected paths", 1)[1].split(
        "- name: Commit", 1
    )[0]
    download = text.split("- name: Download the data artifact", 1)[1].split(
        "- name: Refuse", 1
    )[0]
    commit = text.split("- name: Commit, push and open or update the pull request", 1)[
        1
    ]
    assert "secrets." not in refuse
    assert "GH_TOKEN" not in refuse
    assert "secrets." not in download
    assert "GH_TOKEN:" in commit
    assert "secrets.DATA_PR_TOKEN || github.token" in commit
    checkout = text.split("- name: Check out the repository", 1)[1].split(
        "- name: Keep", 1
    )[0]
    assert "secrets.DATA_PR_TOKEN || github.token" in checkout


def test_actionlint_is_clean():
    binary = shutil.which("actionlint")
    if binary is None:
        pytest.skip("actionlint is not installed")
    result = subprocess.run(
        [binary, str(WORKFLOW)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _workflow_default_allowed(text: str) -> str:
    marker = "default: '"
    start = text.index(marker) + len(marker)
    end = text.index("'", start)
    return text[start:end]


def _repo(tmp: Path) -> tuple[Path, Path, dict[str, str]]:
    env = _git_env(tmp)
    bare = tmp / "origin.git"
    work = tmp / "work"
    _run_git(["git", "init", "--bare", "-q", "-b", "main", str(bare)], env)
    _run_git(["git", "init", "-q", "-b", "main", str(work)], env)
    _run_git(["git", "-C", str(work), "remote", "add", "origin", str(bare)], env)
    (work / "README.md").write_text("hello\n", encoding="utf-8")
    (work / "feeds").mkdir()
    (work / "feeds" / "catalogue.yaml").write_text("old\n", encoding="utf-8")
    (work / "mcp" / "cisa-kev" / "data").mkdir(parents=True)
    (work / "mcp" / "cisa-kev" / "data" / "kev.json").write_text(
        "{}\n", encoding="utf-8"
    )
    _commit_all(work, env, "Initial")
    _run_git(["git", "-C", str(work), "push", "-q", "-u", "origin", "main"], env)
    return work, bare, env


def _git_env(tmp: Path) -> dict[str, str]:
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("GIT_"):
            env.pop(key)
    config = tmp / "gitconfig"
    config.write_text("", encoding="utf-8")
    env["GIT_CONFIG_GLOBAL"] = str(config)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GH_PROMPT_DISABLED"] = "1"
    env["DATA_PR_DATE"] = "2026-10-17"
    env["ALLOWED_PATHS"] = data_update_pr.DEFAULT_ALLOWED
    env["BRANCH_PREFIX"] = "data/intel-refresh"
    env["TITLE"] = "Refresh threat intel snapshots"
    env["BODY_FILE"] = "PR_BODY.md"
    env["LABELS"] = "type:task,area:ci"
    env["GH_TOKEN"] = SECRET
    env["PATH"] = os.environ.get("PATH", "")
    return env


def _install_gh(tmp: Path, env: dict[str, str], *, leak: bool = False) -> Path:
    bindir = tmp / "bin"
    bindir.mkdir()
    log = tmp / "gh.log"
    existing = tmp / "gh-existing.txt"
    script = bindir / "gh"
    script.write_text(f"#!{sys.executable}\n{FAKE_GH}", encoding="utf-8")
    script.chmod(0o755)
    env["PATH"] = str(bindir) + os.pathsep + env["PATH"]
    env["GH_LOG"] = str(log)
    env["GH_EXISTING"] = str(existing)
    if leak:
        env["GH_FAKE_LEAK"] = "1"
    return log


def _plant_hooks(work: Path, tmp: Path) -> None:
    hooks = work / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    marker = tmp / "hook-ran"
    body = f"#!/bin/sh\necho hook-ran > {marker}\nexit 1\n"
    for name in ("pre-commit", "pre-push", "post-checkout"):
        hook = hooks / name
        hook.write_text(body, encoding="utf-8")
        hook.chmod(0o755)


def _run(
    repo: Path, env: dict[str, str], *args: str
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=repo,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    secret = env.get("GH_TOKEN", "")
    if len(secret) >= 8:
        assert secret not in result.stdout
        assert secret not in result.stderr
    return result


def _commit_all(repo: Path, env: dict[str, str], message: str) -> None:
    _git(repo, env, "add", "-A")
    _git(
        repo,
        env,
        "-c",
        "user.name=Test User",
        "-c",
        "user.email=test@example.com",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "-m",
        message,
    )


def _git(
    repo: Path, env: dict[str, str], *args: str
) -> subprocess.CompletedProcess[str]:
    return _run_git(["git", "-C", str(repo), *args], env)


def _run_git(
    command: list[str], env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command, env=env, check=False, capture_output=True, text=True
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    return result


def _rev(repo: Path, ref: str, env: dict[str, str]) -> str:
    return _git(repo, env, "rev-parse", ref).stdout.strip()


def _current_branch(repo: Path, env: dict[str, str]) -> str:
    return _git(repo, env, "branch", "--show-current").stdout.strip()


def _remote_heads(repo: Path, env: dict[str, str]) -> set[str]:
    listed = _git(repo, env, "ls-remote", "--heads", "origin").stdout
    heads = set()
    for line in listed.splitlines():
        _sha, ref = line.split()
        assert ref.startswith("refs/heads/")
        heads.add(ref.removeprefix("refs/heads/"))
    return heads


def _gh_calls(log: Path) -> list[list[str]]:
    if not log.exists():
        return []
    return [
        json.loads(line)
        for line in log.read_text(encoding="utf-8").splitlines()
        if line
    ]
