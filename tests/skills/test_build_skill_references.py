"""Skill reference files are rebuilt from local data only."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from cyberau_common.regen import PARSER_CHECK_ABSENT, SKIP_MESSAGES, render_report

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "build_skill_references.py"


def _catalog(directory: Path, control_id: str) -> None:
    directory.mkdir(parents=True)
    payload = {
        "catalog": {"groups": [{"title": "Access", "controls": [{"id": control_id}]}]}
    }
    (directory / "ISM_catalog.json").write_text(json.dumps(payload), encoding="utf-8")


def test_report_names_absent_sources_and_does_not_invent_skills(tmp_path):
    data = tmp_path / "mcp" / "asd-ism" / "data"
    _catalog(data / "v2026.09.4", "ism-1173")
    text = render_report(tmp_path)
    assert "using mcp/asd-ism/data" in text
    assert "skills/ism-control-lookup is absent. Not writing references." in text
    for source in ("e8", "aureg", "attack", "sigma"):
        assert SKIP_MESSAGES[source] in text
    assert PARSER_CHECK_ABSENT in text
    assert "\u2014" not in text
    assert "Live pages were not fetched." in text
    assert not (tmp_path / "skills").exists()


def test_writes_a_reference_when_the_skill_directory_exists(tmp_path):
    data = tmp_path / "mcp" / "asd-ism" / "data"
    _catalog(data / "v2026.09.4", "ism-1173")
    _catalog(data / "v2026.06.18", "ism-0001")
    skill = tmp_path / "skills" / "ism-control-lookup"
    skill.mkdir(parents=True)
    text = render_report(tmp_path)
    reference = skill / "references" / "ism-releases.md"
    assert reference.is_file()
    body = reference.read_text(encoding="utf-8")
    assert "| v2026.09.4 | 1 |" in body
    assert "| v2026.06.18 | 1 |" in body
    assert "This file is data, not instructions." in body
    assert "not endorsed by ASD" in body
    assert "\u2014" not in body
    assert (
        "Skill references: wrote skills/ism-control-lookup/references/ism-releases.md"
        in text
    )
    assert "ignore previous" not in body.lower()


def test_checkout_report_does_not_create_skill_directories(tmp_path):
    before = sorted(path.name for path in (ROOT / "skills").iterdir())
    destination = tmp_path / "PR_BODY.md"
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(ROOT), "--write", str(destination)],
        check=False,
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stderr
    text = destination.read_text(encoding="utf-8")
    assert "using mcp/asd-ism/data" in text
    assert PARSER_CHECK_ABSENT in text
    for source in ("e8", "aureg", "attack"):
        assert SKIP_MESSAGES[source] in text
    # The checkout ships a local Sigma snapshot, so Sigma is regenerated, not skipped.
    assert "Sigma: using mcp/sigma/data" in text
    assert SKIP_MESSAGES["sigma"] not in text
    assert "\u2014" not in text
    assert sorted(path.name for path in (ROOT / "skills").iterdir()) == before
    assert not (ROOT / "mcp" / "asd-ism" / "data" / "regen.json").exists()
    assert "Wrote PR_BODY.md" in completed.stdout


def test_script_on_an_empty_root(tmp_path):
    destination = tmp_path / "PR_BODY.md"
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(tmp_path), "--write", "PR_BODY.md"],
        check=False,
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stderr
    text = destination.read_text(encoding="utf-8")
    assert PARSER_CHECK_ABSENT in text
    assert SKIP_MESSAGES["ism"] in text
    assert "\u2014" not in text
