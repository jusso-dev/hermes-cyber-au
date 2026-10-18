"""Release notes for SOUL.md, skills and cron jobs."""

from __future__ import annotations

import difflib
import json
import subprocess
import tempfile
from pathlib import Path


def render_release_notes(
    before: Path | None,
    after: Path,
    *,
    version: str | None = None,
    baseline_name: str | None = None,
) -> str:
    """Describe SOUL, skill and cron changes between two trees.

    ``before`` is None when there is no baseline. The notes then list the
    tree being packaged, line by line and job by job.
    """
    title = f"# cyber-au {version}" if version else "# cyber-au"
    lines = [
        title,
        "",
        "Review this list before `hermes profile update`.",
        "New cron jobs arrive paused. SOUL.md and skills apply on the next chat.",
        "",
    ]
    if baseline_name:
        lines.append(f"Compared with `{baseline_name}`.")
    else:
        lines.append("This list is the tree being packaged.")
    lines.append("")
    if before is None:
        lines.extend(_soul_shipped(after))
        lines.extend(_skills_shipped(after))
        lines.extend(_cron_shipped(after))
    else:
        lines.extend(_soul_diff(before, after))
        lines.extend(_skills_diff(before, after))
        lines.extend(_cron_diff(before, after))
    return "\n".join(lines).rstrip() + "\n"


def notes_since_ref(repo: Path, ref: str, *, version: str | None = None) -> str:
    """Diff the working tree against one git ref."""
    snapshot = Path(tempfile.mkdtemp(prefix="cyberau-baseline-"))
    try:
        snapshot_ref(repo, ref, snapshot)
        return render_release_notes(snapshot, repo, version=version, baseline_name=ref)
    finally:
        _remove_tree(snapshot)


def snapshot_ref(repo: Path, ref: str, dest: Path) -> None:
    """Copy SOUL.md, skills and cron/jobs.json from a git ref."""
    known = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
        cwd=repo,
        capture_output=True,
        check=False,
    )
    if known.returncode != 0:
        raise ValueError(f"baseline is not a commit in this repository: {ref}")
    dest.mkdir(parents=True, exist_ok=True)
    _git_file(repo, ref, "SOUL.md", dest / "SOUL.md")
    _git_file(repo, ref, "cron/jobs.json", dest / "cron" / "jobs.json")
    listing = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", ref, "skills"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if listing.returncode != 0:
        return
    for rel in listing.stdout.splitlines():
        parts = Path(rel).parts
        if any(part.startswith(".") for part in parts):
            continue
        _git_file(repo, ref, rel, dest / rel)


def _git_file(repo: Path, ref: str, rel: str, dest: Path) -> None:
    show = subprocess.run(
        ["git", "show", f"{ref}:{rel}"],
        cwd=repo,
        capture_output=True,
        check=False,
    )
    if show.returncode != 0:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(show.stdout)


def _remove_tree(path: Path) -> None:
    if not path.exists():
        return
    for child in sorted(path.rglob("*"), reverse=True):
        if child.is_file() or child.is_symlink():
            child.unlink()
        else:
            child.rmdir()
    path.rmdir()


def _read(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def _lines(text: str) -> list[str]:
    return text.replace("\r\n", "\n").replace("\r", "\n").splitlines()


def _soul_diff(before: Path, after: Path) -> list[str]:
    changes = _line_changes(_read(before / "SOUL.md"), _read(after / "SOUL.md"))
    out = ["## SOUL.md", ""]
    if not changes:
        out.append("No line changes.")
    else:
        out.extend(changes)
    out.append("")
    return out


def _soul_shipped(after: Path) -> list[str]:
    rows = _lines(_read(after / "SOUL.md"))
    out = ["## SOUL.md", ""]
    if not rows:
        out.append("SOUL.md is empty.")
    else:
        out.extend(f"- Line {number}: {text}" for number, text in enumerate(rows, start=1))
    out.append("")
    return out


def _line_changes(before: str, after: str) -> list[str]:
    old = _lines(before)
    new = _lines(after)
    changes: list[str] = []
    matcher = difflib.SequenceMatcher(a=old, b=new)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if tag in {"replace", "delete"}:
            for number, text in enumerate(old[i1:i2], start=i1 + 1):
                changes.append(f"- Line {number} removed: {_show(text)}")
        if tag in {"replace", "insert"}:
            for number, text in enumerate(new[j1:j2], start=j1 + 1):
                changes.append(f"- Line {number} added: {_show(text)}")
    return changes


def _show(text: str) -> str:
    return text if text else "(blank line)"


def _skill_map(root: Path) -> dict[str, dict[str, bytes]]:
    base = root / "skills"
    found: dict[str, dict[str, bytes]] = {}
    if not base.is_dir():
        return found
    for child in sorted(base.iterdir()):
        if child.name.startswith("."):
            continue
        files: dict[str, bytes] = {}
        paths = [child] if child.is_file() else sorted(p for p in child.rglob("*") if p.is_file())
        for path in paths:
            parts = path.relative_to(base).parts
            # Bytecode caches are build output, not shipped skill files (package.py skips them too).
            if any(part.startswith(".") or part == "__pycache__" for part in parts):
                continue
            rel = path.relative_to(child if child.is_dir() else child.parent).as_posix()
            if child.is_file():
                rel = child.name
            # Compare bytes so a binary asset in a skill cannot break the notes.
            files[rel] = path.read_bytes()
        found[child.name] = files
    return found


def _skills_diff(before: Path, after: Path) -> list[str]:
    old = _skill_map(before)
    new = _skill_map(after)
    out = ["## Skills", ""]
    names = sorted(set(old) | set(new))
    rows: list[str] = []
    for name in names:
        if name not in old:
            rows.append(f"- Added `{name}`")
            continue
        if name not in new:
            rows.append(f"- Removed `{name}`")
            continue
        changed = sorted(set(old[name]) | set(new[name]))
        changed = [rel for rel in changed if old[name].get(rel) != new[name].get(rel)]
        if changed:
            rows.append(f"- Changed `{name}`")
            rows.extend(f"  - `{rel}`" for rel in changed)
    out.append("\n".join(rows) if rows else "No skill changes.")
    out.append("")
    return out


def _skills_shipped(after: Path) -> list[str]:
    skills = _skill_map(after)
    out = ["## Skills", ""]
    if not skills:
        out.append("No skills in this tree.")
    else:
        out.extend(f"- `{name}`" for name in sorted(skills))
    out.append("")
    return out


def _jobs(root: Path) -> dict[str, dict]:
    path = root / "cron" / "jobs.json"
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    jobs = data.get("jobs") or []
    found: dict[str, dict] = {}
    for job in jobs:
        job_id = job.get("id")
        if not isinstance(job_id, str) or not job_id:
            raise ValueError("cron job is missing id")
        found[job_id] = job
    return found


def _cron_diff(before: Path, after: Path) -> list[str]:
    old = _jobs(before)
    new = _jobs(after)
    out = ["## Cron jobs", ""]
    rows: list[str] = []
    for job_id in sorted(set(old) | set(new)):
        if job_id not in old:
            rows.append(f"- Added `{job_id}`")
            continue
        if job_id not in new:
            rows.append(f"- Removed `{job_id}`")
            continue
        fields = sorted(set(old[job_id]) | set(new[job_id]))
        changed = [field for field in fields if old[job_id].get(field) != new[job_id].get(field)]
        if changed:
            rows.append(f"- Changed `{job_id}`")
            rows.extend(f"  - `{field}`" for field in changed)
    out.append("\n".join(rows) if rows else "No cron job changes.")
    out.append("")
    return out


def _cron_shipped(after: Path) -> list[str]:
    jobs = _jobs(after)
    out = ["## Cron jobs", ""]
    if not jobs:
        out.append("No cron jobs in this tree.")
    else:
        out.extend(f"- `{job_id}`" for job_id in sorted(jobs))
    out.append("")
    return out
