"""Supply chain checks: lock hashes, SBOM, release notes, attestations."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import tarfile
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str):
    path = ROOT / "tools" / "release" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"cyberau_release_{name}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


notes = _load("notes")
sbom = _load("sbom")
package = _load("package")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_release_notes_cover_soul_skills_and_cron(tmp_path: Path):
    before = tmp_path / "before"
    after = tmp_path / "after"
    _write(before / "SOUL.md", "# cyber-au\n\nKeep the old rule.\n")
    _write(after / "SOUL.md", "# cyber-au\n\nKeep the new rule.\nCite the source.\n")
    _write(before / "skills" / "incident-triage" / "SKILL.md", "Old skill\n")
    _write(after / "skills" / "incident-triage" / "SKILL.md", "New skill\n")
    _write(before / "skills" / "old-skill" / "SKILL.md", "Retire me\n")
    _write(after / "skills" / "phishing-analysis" / "SKILL.md", "Phish\n")
    _write(
        before / "cron" / "jobs.json",
        json.dumps(
            {
                "jobs": [
                    {"id": "cyberau-morning-brief", "schedule": "every 1d at 07:30"},
                    {"id": "cyberau-old", "schedule": "every 1h"},
                ]
            }
        ),
    )
    _write(
        after / "cron" / "jobs.json",
        json.dumps(
            {
                "jobs": [
                    {"id": "cyberau-morning-brief", "schedule": "every 1d at 08:00"},
                    {"id": "cyberau-kev-watch", "schedule": "every 6h"},
                ]
            }
        ),
    )

    text = notes.render_release_notes(before, after, version="2026.10.17", baseline_name="v0")

    assert "\u2014" not in text
    assert "Line 3 removed: Keep the old rule." in text
    assert "Line 3 added: Keep the new rule." in text
    assert "Line 4 added: Cite the source." in text
    assert "Added `phishing-analysis`" in text
    assert "Removed `old-skill`" in text
    assert "Changed `incident-triage`" in text
    assert "`SKILL.md`" in text
    assert "Added `cyberau-kev-watch`" in text
    assert "Removed `cyberau-old`" in text
    assert "Changed `cyberau-morning-brief`" in text
    assert "`schedule`" in text
    assert "Compared with `v0`." in text


def test_release_notes_from_a_git_ref(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "Supply Chain Test",
            "GIT_AUTHOR_EMAIL": "supply-chain-test@example.com",
            "GIT_COMMITTER_NAME": "Supply Chain Test",
            "GIT_COMMITTER_EMAIL": "supply-chain-test@example.com",
        }
    )

    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=repo, check=True, env=env, capture_output=True)

    git("init")
    _write(repo / "SOUL.md", "First line\n")
    _write(repo / "skills" / "ism-control-lookup" / "SKILL.md", "Lookup\n")
    _write(
        repo / "cron" / "jobs.json",
        json.dumps({"jobs": [{"id": "cyberau-old", "schedule": "every 1h"}]}),
    )
    git("add", "SOUL.md", "skills", "cron/jobs.json")
    git("commit", "-m", "base")
    git("tag", "v0")
    _write(repo / "SOUL.md", "First line\nSecond line\n")
    _write(repo / "skills" / "phishing-analysis" / "SKILL.md", "Phish\n")
    _write(
        repo / "cron" / "jobs.json",
        json.dumps({"jobs": [{"id": "cyberau-kev-watch", "schedule": "every 6h"}]}),
    )
    git("add", "SOUL.md", "skills", "cron/jobs.json")
    git("commit", "-m", "next")

    text = notes.notes_since_ref(repo, "v0", version="2026.10.17")
    assert "Line 2 added: Second line" in text
    assert "Added `phishing-analysis`" in text
    assert "Removed `cyberau-old`" in text
    assert "Added `cyberau-kev-watch`" in text
    assert "Compared with `v0`." in text


def test_sbom_lists_every_runtime_lock_dependency(tmp_path: Path):
    lock = ROOT / "mcp" / "uv.lock"
    expected = sbom.runtime_packages(lock)
    names = {name for name, _version in expected}
    assert "httpx" in names
    assert "pytest" not in names
    assert "cyclonedx-bom" not in names
    assert "colorama" not in names

    bom = sbom.write_sbom(ROOT, tmp_path / "sbom.cdx.json")
    assert bom["bomFormat"] == "CycloneDX"
    assert sbom.cyclonedx_tool(bom).startswith("cyclonedx-py")
    found = {(component["name"], component["version"]) for component in bom["components"]}
    missing = [item for item in expected if item not in found]
    assert missing == []
    for component in bom["components"]:
        hashes = [
            digest
            for ref in component.get("externalReferences") or []
            for digest in ref.get("hashes") or []
        ]
        assert any(item.get("alg") == "SHA-256" and item.get("content") for item in hashes)


def test_lock_hashes_and_frozen_installs():
    gaps = sbom.registry_hash_gaps(ROOT / "mcp" / "uv.lock")
    assert gaps == []
    offenders = []
    for directory in (ROOT / ".github" / "workflows", ROOT / ".github" / "workflows"):
        for path in directory.glob("*.yml"):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if "uv sync" in line and "--frozen" not in line:
                    offenders.append(f"{path.relative_to(ROOT)}:{number}")
    assert offenders == []


def test_direct_dependencies_have_upper_bounds():
    bare = re.compile(r"^[A-Za-z0-9_.-]+$")
    for path in (ROOT / "mcp").rglob("pyproject.toml"):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        specs = list(data.get("project", {}).get("dependencies") or [])
        for group in (data.get("dependency-groups") or {}).values():
            specs.extend(group)
        for spec in specs:
            if bare.fullmatch(spec):
                continue
            assert "<" in spec, f"{path.relative_to(ROOT)}: {spec}"


def test_dependabot_covers_uv_and_actions():
    text = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    updates = data["updates"]
    by_eco = {item["package-ecosystem"]: item for item in updates}
    assert set(by_eco) == {"uv", "github-actions"}
    assert by_eco["uv"]["directory"] == "/mcp"
    assert by_eco["github-actions"]["directory"] == "/"
    assert by_eco["uv"]["open-pull-requests-limit"] == 5
    assert text.count('time: "09:00"') == 2
    assert text.count('timezone: "Australia/Sydney"') == 2
    assert text.count('day: "monday"') == 2


def test_docs_recommend_install_ref_over_main():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    doc = (ROOT / "docs" / "operations" / "supply-chain.md").read_text(encoding="utf-8")
    for text in (readme, doc):
        assert "install.sh --ref <tag>" in text or "install.sh --ref" in text
        assert "main" in text
        assert "\u2014" not in text
    assert "cyclonedx-py" in doc
    assert "actions/attest-build-provenance" in doc
    assert "signing key" in doc
    assert "BEGIN PRIVATE KEY" not in doc


def test_release_workflow_attests_files_and_image():
    text = (ROOT / ".github" / "workflows" / "weekly-release.yml").read_text(encoding="utf-8")
    pinned = "actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be # v2"
    assert text.count(pinned) == 2
    assert "subject-path: dist/*" in text
    assert "subject-digest:" in text
    assert "push-to-registry: true" in text
    assert "--notes-file dist/RELEASE_NOTES.md" in text
    assert "--generate-notes" not in text
    assert "BEGIN PRIVATE KEY" not in text
    assert "cosign.key" not in text


def test_package_writes_tarball_sbom_and_notes_without_a_signature(tmp_path: Path):
    out = tmp_path / "dist"
    assert (
        package.main(
            [
                "--version",
                "2026.10.17",
                "--out",
                str(out),
                "--baseline",
                "none",
                "--root",
                str(ROOT),
            ]
        )
        == 0
    )
    sbom_path = out / "cyber-au-2026.10.17.cdx.json"
    notes_path = out / "RELEASE_NOTES.md"
    provenance_path = out / "provenance.json"
    archive_path = out / "cyber-au-2026.10.17.tar.gz"
    assert sbom_path.is_file()
    assert "SOUL.md" in notes_path.read_text(encoding="utf-8")
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    assert provenance["sbom_tool"].startswith("cyclonedx-py")
    assert provenance["lock"] == "mcp/uv.lock"
    assert re.fullmatch(r"[0-9a-f]{64}", provenance["lock_sha256"])
    assert "signature" not in provenance
    assert "BEGIN PRIVATE KEY" not in provenance_path.read_text(encoding="utf-8")
    with tarfile.open(archive_path, "r:gz") as archive:
        names = archive.getnames()
    assert "cyber-au-2026.10.17/SOUL.md" in names
    assert "cyber-au-2026.10.17/cyber-au-2026.10.17.cdx.json" in names
    assert "cyber-au-2026.10.17/provenance.json" in names
    assert not any(name.endswith(".pem") or name.endswith(".key") for name in names)
    bom = json.loads(sbom_path.read_text(encoding="utf-8"))
    found = {(component["name"], component["version"]) for component in bom["components"]}
    missing = [
        item for item in sbom.runtime_packages(ROOT / "mcp" / "uv.lock") if item not in found
    ]
    assert missing == []


def _git_repo(path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "Supply Chain Test",
            "GIT_AUTHOR_EMAIL": "supply-chain-test@example.com",
            "GIT_COMMITTER_NAME": "Supply Chain Test",
            "GIT_COMMITTER_EMAIL": "supply-chain-test@example.com",
        }
    )
    subprocess.run(["git", "init"], cwd=path, check=True, env=env, capture_output=True)
    return env


def test_tarball_ships_tracked_files_only_and_keeps_env_template(tmp_path: Path):
    repo = tmp_path / "repo"
    _write(
        repo / "distribution.yaml",
        "name: cyber-au\nversion: 0.1.0\ndistribution_owned:\n  - SOUL.md\n"
        "  - .env.template\n  - mcp\n",
    )
    _write(repo / "SOUL.md", "Soul\n")
    _write(repo / ".env.template", "# KEY=\n")
    _write(repo / "mcp" / "uv.lock", "version = 1\n")
    _write(repo / "mcp" / "kept.py", "x = 1\n")
    env = _git_repo(repo)
    subprocess.run(["git", "add", "."], cwd=repo, check=True, env=env, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "base"], cwd=repo, check=True, env=env, capture_output=True
    )
    _write(repo / "mcp" / ".hypothesis" / "scrap", "local cache\n")
    _write(repo / "mcp" / "untracked.py", "y = 2\n")
    _write(repo / ".env", "SECRET=1\n")

    archive_path = tmp_path / "out.tar.gz"
    package._write_archive(repo.resolve(), archive_path, "p", {})
    with tarfile.open(archive_path, "r:gz") as archive:
        names = set(archive.getnames())
    assert names == {"p/SOUL.md", "p/.env.template", "p/mcp/uv.lock", "p/mcp/kept.py"}


def test_provenance_commit_is_this_checkout_and_flags_a_dirty_tree(tmp_path: Path):
    outer = tmp_path / "outer"
    inner = outer / "inner"
    inner.mkdir(parents=True)
    env = _git_repo(outer)
    _write(outer / "file.txt", "x\n")
    subprocess.run(["git", "add", "."], cwd=outer, check=True, env=env, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "base"], cwd=outer, check=True, env=env, capture_output=True
    )

    assert package._git_commit(inner.resolve()) is None
    assert package._git_commit(outer.resolve()) is not None
    assert package._git_dirty(outer.resolve()) is False
    _write(outer / "file.txt", "changed\n")
    assert package._git_dirty(outer.resolve()) is True


def test_package_provenance_records_commit_and_lock_hash(tmp_path: Path):
    import hashlib

    out = tmp_path / "dist"
    package.main(["--version", "2026.10.17", "--out", str(out), "--baseline", "none"])
    provenance = json.loads((out / "provenance.json").read_text(encoding="utf-8"))
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    assert provenance["git_commit"] == head
    assert isinstance(provenance["git_dirty"], bool)
    lock = (ROOT / "mcp" / "uv.lock").read_bytes()
    assert provenance["lock_sha256"] == hashlib.sha256(lock).hexdigest()


def test_unknown_baseline_is_an_error_not_an_empty_diff(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    env = _git_repo(repo)
    _write(repo / "SOUL.md", "x\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, env=env, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "base"], cwd=repo, check=True, env=env, capture_output=True
    )
    try:
        notes.notes_since_ref(repo, "no-such-tag", version="1")
    except ValueError as error:
        assert "no-such-tag" in str(error)
    else:
        raise AssertionError("an unknown baseline produced notes")


def test_image_steps_wait_for_a_dockerfile():
    text = (ROOT / ".github" / "workflows" / "weekly-release.yml").read_text(encoding="utf-8")
    assert text.count("hashFiles('docker/Dockerfile') != ''") == 2
