"""Commit data updates onto a dated branch and open or update one pull request.

``.github/workflows/data-update-pr.yml`` calls this script. Data updates never
touch ``.github/``: those paths are refused, because pushing a workflow file
needs a token with the workflows permission, which the data token does not have.

Paths outside the caller's allowed data directories are refused, as are
symlinks and other non-regular entries inside them. The script
never pushes to main or master. Git hooks are taken from an empty directory so
a data artifact cannot plant ``.git/hooks`` and run them during the commit or
the push.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from zoneinfo import ZoneInfo

DEFAULT_ALLOWED = (
    r"^(mcp/[a-z0-9-]+/data/|feeds/|"
    r"skills/[a-z0-9-]+/references/|PR_BODY\.md$)"
)

NO_CHANGE = "No change. No pull request."
REFUSE = "Data update touched files outside the data paths. Refusing."

BOT_NAME = "cyber-au data bot"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"

_PROTECTED = frozenset({"main", "master"})
_PROTECTED_REFS = frozenset({"refs/heads/main", "refs/heads/master"})
_PREFIX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*[A-Za-z0-9]$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
_HOOKS: str | None = None


class DataPrError(Exception):
    """The data update cannot be published."""


def redact(text: str, secret: str) -> str:
    if len(secret) < 8:
        return text
    return text.replace(secret, "[redacted]")


def compile_allowed(raw: str | None) -> re.Pattern[str]:
    pattern = DEFAULT_ALLOWED if raw is None else raw
    if pattern.strip() == "":
        raise DataPrError("ALLOWED_PATHS is empty.")
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise DataPrError("ALLOWED_PATHS is not a valid regular expression.") from exc


def allowed_from_env() -> re.Pattern[str]:
    if "ALLOWED_PATHS" not in os.environ:
        return compile_allowed(None)
    return compile_allowed(os.environ["ALLOWED_PATHS"])


def is_allowed(path: str, pattern: re.Pattern[str]) -> bool:
    if not path or path.endswith("/"):
        return False
    if any(char in path for char in "\n\r\0"):
        return False
    parts = path.split("/")
    if path.startswith("/") or ".." in parts or parts[0] in {".git", ".github"}:
        return False
    return pattern.search(path) is not None


def parse_porcelain_z(blob: str) -> list[str]:
    if not blob:
        return []
    parts = blob.split("\0")
    if parts and parts[-1] == "":
        parts.pop()
    paths: list[str] = []
    index = 0
    while index < len(parts):
        record = parts[index]
        if len(record) < 4 or record[2] != " ":
            raise DataPrError("Unrecognised git status record.")
        status = record[:2]
        paths.append(record[3:])
        if "R" in status or "C" in status:
            index += 1
            if index >= len(parts):
                raise DataPrError("Rename record is missing the original path.")
            paths.append(parts[index])
        index += 1
    return paths


def today_sydney(now=None) -> str:
    override = os.environ.get("DATA_PR_DATE", "").strip()
    if override:
        _require_date(override, "DATA_PR_DATE must be YYYY-MM-DD.")
        return override
    clock = now or (lambda: datetime.now(ZoneInfo("UTC")))
    current = clock()
    if current.tzinfo is None:
        raise DataPrError("The clock must be timezone-aware.")
    return current.astimezone(ZoneInfo("Australia/Sydney")).date().isoformat()


def dated_branch(prefix: str, day: str) -> str:
    if (
        not _PREFIX_RE.fullmatch(prefix)
        or ".." in prefix
        or "//" in prefix
        or prefix.startswith("refs/")
        or prefix.endswith("/")
    ):
        raise DataPrError("Refusing an unsafe branch prefix.")
    _require_date(day, "Refusing an unsafe branch date.")
    branch = f"{prefix}/{day}"
    push_refspec(branch)
    return branch


def push_refspec(branch: str) -> str:
    protected_child = tuple(f"{name}/" for name in _PROTECTED)
    if branch in _PROTECTED or branch.startswith(protected_child):
        raise DataPrError("Refusing to push the default branch.")
    if (
        not _BRANCH_RE.fullmatch(branch)
        or ".." in branch
        or "//" in branch
        or "@{" in branch
        or branch.endswith(".lock")
        or branch.startswith("refs/")
    ):
        raise DataPrError("Refusing an unsafe branch name.")
    destination = f"refs/heads/{branch}"
    if destination in _PROTECTED_REFS:
        raise DataPrError("Refusing to push the default branch.")
    spec = f"{destination}:{destination}"
    if spec.split(":") != [destination, destination]:
        raise DataPrError("Refusing an unsafe branch name.")
    return spec


def parse_title(raw: str) -> str:
    if not raw.strip() or any(char in raw for char in "\r\n"):
        raise DataPrError("TITLE must be a single non-empty line.")
    return raw


def parse_labels(raw: str) -> list[str]:
    labels: list[str] = []
    for part in raw.split(","):
        label = part.strip()
        if not label:
            continue
        if any(char in label for char in "\r\n\t") or not label.isprintable():
            raise DataPrError("Refusing an unsafe label.")
        labels.append(label)
    return labels


def parse_body_file(repo: Path, raw: str) -> str:
    relative = raw
    parts = relative.split("/")
    if (
        not relative
        or relative.startswith(("/", "\\"))
        or ".." in parts
        or any(char in relative for char in "\r\n\0")
    ):
        raise DataPrError("BODY_FILE must stay inside the repository.")
    path = (repo / relative).resolve()
    root = repo.resolve()
    if path != root and root not in path.parents:
        raise DataPrError("BODY_FILE must stay inside the repository.")
    # Compare against git's own spelling of the path, so "feeds//b.md" and
    # "./feeds/b.md" are still left out of the commit.
    return PurePosixPath(relative).as_posix()


def refuse() -> int:
    repo = repo_root()
    rejected = reject_unexpected(changed_paths(repo), allowed_from_env(), repo)
    return 0 if rejected is None else rejected


def open_pr() -> int:
    repo = repo_root()
    pattern = allowed_from_env()
    branch = dated_branch(os.environ.get("BRANCH_PREFIX", ""), today_sydney())
    title = parse_title(os.environ.get("TITLE", ""))
    labels = parse_labels(os.environ.get("LABELS", ""))
    body_rel = parse_body_file(repo, os.environ.get("BODY_FILE", ""))
    paths = changed_paths(repo)
    rejected = reject_unexpected(paths, pattern, repo)
    if rejected is not None:
        return rejected
    committable = [path for path in paths if path != body_rel]
    if not committable:
        print(NO_CHANGE)
        return 0
    if not (repo / body_rel).is_file():
        raise DataPrError("BODY_FILE is missing.")
    token = require_token()
    _git(["checkout", "-B", branch], repo)
    _require_head(repo, branch)
    _git(["reset", "-q", "--", "."], repo)
    _git(["--literal-pathspecs", "add", "-A", "--", *committable], repo)
    staged = staged_paths(repo)
    extra = [path for path in staged if path not in committable or not is_allowed(path, pattern)]
    if extra:
        return _refuse_paths(extra)
    if not staged:
        print(NO_CHANGE)
        return 0
    _git(
        [
            "-c",
            f"user.name={BOT_NAME}",
            "-c",
            f"user.email={BOT_EMAIL}",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            title,
        ],
        repo,
        identity=True,
    )
    _require_head(repo, branch)
    destination = push_refspec(branch).split(":")[0]
    print(f"Pushing {destination}.")
    publish(repo, branch)
    number = existing_pr(repo, branch, token)
    if number:
        _gh(["pr", "edit", number, "--body-file", body_rel], repo, token)
        print(f"Updated pull request {number}.")
    else:
        command = [
            "pr",
            "create",
            "--base",
            "main",
            "--head",
            branch,
            "--title",
            title,
            "--body-file",
            body_rel,
        ]
        for label in labels:
            command.extend(["--label", label])
        _gh(command, repo, token)
        print("Opened a pull request.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if args == ["refuse"]:
            return refuse()
        if args == ["open"]:
            return open_pr()
    except DataPrError as exc:
        print(exc, file=sys.stderr)
        return 1
    print("usage: data_update_pr.py refuse|open", file=sys.stderr)
    return 2


def is_plain_file(repo: Path, path: str) -> bool:
    """A deleted path is plain. A symlink or other special entry is not."""
    try:
        mode = (repo / path).lstat().st_mode
    except FileNotFoundError:
        return True
    return stat.S_ISREG(mode)


def reject_unexpected(
    paths: list[str], pattern: re.Pattern[str], repo: Path | None = None
) -> int | None:
    bad = [
        path
        for path in paths
        if not is_allowed(path, pattern) or (repo is not None and not is_plain_file(repo, path))
    ]
    if not bad:
        return None
    return _refuse_paths(bad)


def publish(repo: Path, branch: str) -> None:
    spec = push_refspec(branch)
    destination, rhs = spec.split(":")
    if destination != rhs or destination in _PROTECTED_REFS:
        raise DataPrError("Refusing to push the default branch.")
    _require_head(repo, branch)
    listed = _git(["ls-remote", "--heads", "origin", destination], repo)
    found: list[str] = []
    for line in listed.stdout.splitlines():
        if not line.strip():
            continue
        sha, ref = line.split()
        if ref != destination:
            continue
        if not _SHA_RE.fullmatch(sha):
            raise DataPrError("Refusing an unexpected remote tip.")
        found.append(sha)
    if not found:
        _git(["push", "origin", spec], repo)
        return
    if len(found) != 1:
        raise DataPrError("Refusing to push while the remote branch is ambiguous.")
    lease = f"--force-with-lease={destination}:{found[0]}"
    _git(["push", lease, "origin", spec], repo)


def existing_pr(repo: Path, branch: str, token: str) -> str:
    result = _gh(
        [
            "pr",
            "list",
            "--head",
            branch,
            "--base",
            "main",
            "--state",
            "open",
            "--json",
            "number",
            "--jq",
            ".[0].number // empty",
        ],
        repo,
        token,
    )
    number = result.stdout.strip()
    if not number:
        return ""
    if not number.isdigit():
        raise DataPrError("Could not read the existing pull request number.")
    return number


def changed_paths(repo: Path) -> list[str]:
    result = _git(["status", "--porcelain=v1", "-z", "--untracked-files=all"], repo)
    return parse_porcelain_z(result.stdout)


def staged_paths(repo: Path) -> list[str]:
    result = _git(["diff", "--cached", "--name-only", "-z"], repo)
    return [part for part in result.stdout.split("\0") if part]


def repo_root() -> Path:
    result = _git(["rev-parse", "--show-toplevel"], Path.cwd())
    return Path(result.stdout.strip())


def _require_date(value: str, message: str) -> None:
    if not _DATE_RE.fullmatch(value):
        raise DataPrError(message)
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise DataPrError(message) from exc


def _refuse_paths(paths: list[str]) -> int:
    for path in paths:
        print(path, file=sys.stderr)
    print(REFUSE, file=sys.stderr)
    return 1


def _require_head(repo: Path, branch: str) -> None:
    head = _git(["rev-parse", "--abbrev-ref", "HEAD"], repo).stdout.strip()
    if head in _PROTECTED or head != branch:
        raise DataPrError("Refusing to publish because HEAD is not the dated branch.")


def require_token() -> str:
    token = os.environ.get("GH_TOKEN", "")
    if len(token) < 8 or token != token.strip() or any(char in token for char in "\r\n\t "):
        raise DataPrError("GH_TOKEN is not set.")
    return token


def _hooks_path() -> str:
    global _HOOKS
    if _HOOKS is None:
        _HOOKS = tempfile.mkdtemp(prefix="cyberau-data-pr-hooks-")
    return _HOOKS


def _git(
    args: list[str],
    repo: Path,
    *,
    check: bool = True,
    identity: bool = False,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    if identity:
        env["GIT_AUTHOR_NAME"] = BOT_NAME
        env["GIT_AUTHOR_EMAIL"] = BOT_EMAIL
        env["GIT_COMMITTER_NAME"] = BOT_NAME
        env["GIT_COMMITTER_EMAIL"] = BOT_EMAIL
    result = subprocess.run(
        ["git", "-c", f"core.hooksPath={_hooks_path()}", *args],
        cwd=repo,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="surrogateescape",
    )
    if check and result.returncode != 0:
        secret = os.environ.get("GH_TOKEN", "")
        detail = redact(result.stderr.strip() or result.stdout.strip(), secret)
        raise DataPrError(f"git {_git_command(args)} failed.\n{detail}")
    return result


def _git_command(args: list[str]) -> str:
    skip_value = False
    for arg in args:
        if skip_value:
            skip_value = False
            continue
        if arg == "-c":
            skip_value = True
            continue
        if arg.startswith("-"):
            continue
        return arg
    return "git"


def _gh(args: list[str], repo: Path, token: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["GH_TOKEN"] = token
    env["GH_PROMPT_DISABLED"] = "1"
    env["GH_NO_UPDATE_NOTIFIER"] = "1"
    result = subprocess.run(
        ["gh", *args],
        cwd=repo,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    safe_stdout = redact(result.stdout, token)
    safe_stderr = redact(result.stderr, token)
    if result.returncode != 0:
        verb = " ".join(args[:2]) if args else "gh"
        detail = (safe_stderr or safe_stdout).strip()
        raise DataPrError(f"gh {verb} failed.\n{detail}")
    if safe_stdout != result.stdout:
        raise DataPrError("gh stdout contained the token.")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
