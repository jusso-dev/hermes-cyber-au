"""The pinned guidance pack (ADR 0002, issue #19) must not collide with this distribution.

The pack's skill and tool names are recorded in install/guidance-pack/pin.yaml at the
pinned commit, so this check needs no network.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PIN = ROOT / "install" / "guidance-pack" / "pin.yaml"


def _pin() -> dict:
    return yaml.safe_load(PIN.read_text(encoding="utf-8"))


def _our_skills() -> set[str]:
    names = set()
    for skill in (ROOT / "skills").glob("*/SKILL.md"):
        front = skill.read_text(encoding="utf-8").split("---", 2)[1]
        names.add(yaml.safe_load(front)["name"])
    return names


def _our_tools() -> set[str]:
    manifest = yaml.safe_load(
        (ROOT / "plugins" / "cyber-au" / "plugin.yaml").read_text(encoding="utf-8")
    )
    return set(manifest.get("provides_tools") or [])


def test_pin_is_a_full_commit_with_recorded_lists():
    pin = _pin()
    assert pin["repository"] == "jusso-dev/hermes-skills"
    assert pin["path"] == "plugins/hermes-cyber-au"
    assert re.fullmatch(r"[0-9a-f]{40}", pin["commit"])
    assert pin["license"] == "MIT"
    assert pin["skills"] and pin["tools"]


def test_no_skill_name_collides_with_the_guidance_pack():
    assert _our_skills() & set(_pin()["skills"]) == set()


def test_no_tool_name_collides_with_the_guidance_pack():
    ours = _our_tools()
    assert ours, "plugin.yaml lists no tools"
    assert ours & set(_pin()["tools"]) == set()


def test_bootstrap_installs_the_pack_at_the_pin():
    text = (ROOT / "install" / "bootstrap.sh").read_text(encoding="utf-8")
    assert 'plugins install "$source_ref" --force --ref "$commit"' in text
    assert "guidance-pack/pin.yaml" in text
