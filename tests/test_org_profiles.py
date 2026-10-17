"""Five profile overlays. One Hermes distribution installs one home."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cyberau_hindsight.constants import CONNECTOR_KEYS, ROLES
from cyberau_hindsight.profiles import apply_overlay, main, validate_distribution

ROOT = Path(__file__).resolve().parents[1]
OVERLAYS = ROOT / "profiles" / "overlays"

BANNED = [
    "ignore previous",
    "ignore all",
    "ignore prior",
    "disregard",
    "you are now",
    "pretend",
    "system prompt",
    ".env",
    "credentials",
    ".netrc",
    "curl ",
    "wget ",
]


def test_shipped_overlays_are_not_gitignored():
    result = subprocess.run(
        ["git", "check-ignore", "profiles/overlays/watcher/SOUL.md"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0


def test_distribution_documents_overlays_because_one_install_is_one_home():
    text = (ROOT / "profiles" / "README.md").read_text(encoding="utf-8")
    assert "installs one home" in text
    assert "overlay" in text
    assert "reflect" in text.lower()
    assert "\u2014" not in text
    validate_distribution(ROOT)


def test_each_role_has_a_soul_paused_job_and_key_policy():
    origin = []
    for role in ROLES:
        soul = (OVERLAYS / role / "SOUL.md").read_text(encoding="utf-8")
        assert soul.startswith(f"# {role}\n")
        assert "memories/MEMORY.md" in soul
        assert "Do not use reflect." in soul
        assert "I don't know" in soul
        lowered = soul.lower()
        assert "do not send mail" in lowered
        assert "\u2014" not in soul
        for phrase in BANNED:
            assert phrase not in lowered, phrase
        if role == "briefer":
            assert "only profile whose scheduled job may deliver to the owner" in lowered
        else:
            assert "do not deliver to the owner" in lowered
        if role == "watcher":
            assert "only profile that holds connector keys" in lowered
        else:
            assert "do not hold connector keys" in lowered
        job = json.loads((OVERLAYS / role / "cron" / "jobs.json").read_text(encoding="utf-8"))
        assert len(job["jobs"]) == 1
        record = job["jobs"][0]
        assert record["paused"] is True
        assert record["enabled"] is False
        if record["deliver"] == "origin":
            origin.append(role)
        template = (OVERLAYS / role / "env.template").read_text(encoding="utf-8")
        assert f"CYBERAU_PROFILE_ROLE={role}" in template
        for name in CONNECTOR_KEYS:
            if role == "watcher":
                assert name in template
            else:
                assert name not in template
    assert origin == ["briefer"]


def test_apply_writes_the_home_and_does_not_edit_the_checkout(tmp_path: Path):
    soul_before = (ROOT / "SOUL.md").read_text(encoding="utf-8")
    home = tmp_path / "home"
    marker = home / "skills" / "keep.txt"
    marker.parent.mkdir(parents=True)
    marker.write_text("keep", encoding="utf-8")
    assert main(["--role", "briefer", "--home", str(home), "--distribution", str(ROOT)]) == 0
    assert (home / "SOUL.md").read_text(encoding="utf-8").startswith("# briefer")
    assert (ROOT / "SOUL.md").read_text(encoding="utf-8") == soul_before
    assert marker.read_text(encoding="utf-8") == "keep"
    assert not (home / ".env").exists()
    example = (home / ".env.EXAMPLE").read_text(encoding="utf-8")
    assert "HINDSIGHT_READ_ONLY=1" in example
    assert "ABUSECH_AUTH_KEY" not in example
    jobs = json.loads((home / "cron" / "jobs.json").read_text(encoding="utf-8"))
    assert jobs["jobs"][0]["paused"] is True
    assert jobs["jobs"][0]["deliver"] == "origin"
    role = (home / "plugin-data" / "cyber-au" / "profile-role").read_text(encoding="utf-8")
    assert role.strip() == "briefer"
    with pytest.raises(ValueError, match="git checkout"):
        apply_overlay("watcher", ROOT, ROOT)


def test_reapply_keeps_a_job_the_operator_resumed(tmp_path: Path):
    home = tmp_path / "home"
    apply_overlay("watcher", home, ROOT)
    path = home / "cron" / "jobs.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["jobs"][0]["paused"] = False
    data["jobs"][0]["enabled"] = True
    path.write_text(json.dumps(data), encoding="utf-8")
    apply_overlay("watcher", home, ROOT)
    again = json.loads(path.read_text(encoding="utf-8"))["jobs"][0]
    assert again["paused"] is False
    assert again["enabled"] is True
    assert again["deliver"] == "local"


def test_only_the_briefer_may_deliver_to_the_owner(tmp_path: Path):
    dist = tmp_path / "dist"
    shutil.copytree(ROOT / "profiles", dist / "profiles")
    job_path = dist / "profiles" / "overlays" / "analyst" / "cron" / "jobs.json"
    job = json.loads(job_path.read_text(encoding="utf-8"))
    job["jobs"][0]["deliver"] = "origin"
    job_path.write_text(json.dumps(job), encoding="utf-8")
    with pytest.raises(ValueError, match="briefer"):
        validate_distribution(dist)


def _dist_with_env(tmp_path: Path, role: str, text: str) -> Path:
    dist = tmp_path / "dist"
    shutil.copytree(ROOT / "profiles", dist / "profiles")
    (dist / "profiles" / "overlays" / role / "env.template").write_text(text, encoding="utf-8")
    return dist


def test_a_commented_out_line_does_not_satisfy_the_env_policy(tmp_path: Path):
    template = (OVERLAYS / "analyst" / "env.template").read_text(encoding="utf-8")
    commented_ro = template.replace("\nHINDSIGHT_READ_ONLY=1", "\n# HINDSIGHT_READ_ONLY=1")
    assert commented_ro != template
    with pytest.raises(ValueError, match="read-only"):
        validate_distribution(_dist_with_env(tmp_path / "a", "analyst", commented_ro))

    wrong_role = template.replace(
        "\nCYBERAU_PROFILE_ROLE=analyst", "\n# CYBERAU_PROFILE_ROLE=analyst"
    )
    wrong_role += "CYBERAU_PROFILE_ROLE=watcher\n"
    with pytest.raises(ValueError, match="role"):
        validate_distribution(_dist_with_env(tmp_path / "b", "analyst", wrong_role))

    with pytest.raises(ValueError, match="connector key"):
        validate_distribution(
            _dist_with_env(
                tmp_path / "c",
                "skeptic",
                template.replace("analyst", "skeptic") + "NVD_API_KEY=x\n",
            )
        )

    shipped = template + "HINDSIGHT_API_KEY=abc\n"
    with pytest.raises(ValueError, match="must not ship"):
        validate_distribution(_dist_with_env(tmp_path / "d", "analyst", shipped))


def test_apply_does_not_write_through_a_link(tmp_path: Path):
    outside = tmp_path / "checkout" / "SOUL.md"
    outside.parent.mkdir()
    outside.write_text("keep me", encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir()
    (home / "SOUL.md").symlink_to(outside)
    with pytest.raises(ValueError, match="link"):
        apply_overlay("watcher", home, ROOT)
    assert outside.read_text(encoding="utf-8") == "keep me"


def test_changing_role_drops_the_job_another_overlay_shipped(tmp_path: Path):
    home = tmp_path / "home"
    apply_overlay("briefer", home, ROOT)
    path = home / "cron" / "jobs.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["jobs"].append({"id": "own-job", "deliver": "local", "paused": True, "enabled": False})
    path.write_text(json.dumps(data), encoding="utf-8")
    apply_overlay("analyst", home, ROOT)
    ids = [job["id"] for job in json.loads(path.read_text(encoding="utf-8"))["jobs"]]
    assert ids == ["org-analyst-claim", "own-job"]
