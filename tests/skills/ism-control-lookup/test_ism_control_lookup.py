"""ISM control lookup: date rule, structure, and the offline eval. No model."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import date
from pathlib import Path

HARNESS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HARNESS_DIR))

import harness  # noqa: E402  (needs HARNESS_DIR on sys.path)

ROOT = harness.ROOT
SKILL = ROOT / "skills" / "ism-control-lookup"
SCRIPT = SKILL / "scripts" / "release_in_force.py"
EVALS = ROOT / "tests" / "skills" / "ism-control-lookup" / "evals.yaml"
CONNECTOR_RELEASES = ROOT / "mcp" / "asd-ism" / "data" / "releases.json"


def _release_module():
    spec = importlib.util.spec_from_file_location("ism_release_in_force", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_in_force_uses_published_dates():
    choose = _release_module().release_in_force
    releases = json.loads((SKILL / "references" / "releases.json").read_text(encoding="utf-8"))
    rows = releases["releases"]
    assert choose(rows, date(2026, 6, 17)) is None
    assert choose(rows, date(2026, 6, 18)) == "v2026.06.18"
    assert choose(rows, date(2026, 8, 1)) == "v2026.06.18"
    assert choose(rows, date(2026, 9, 2)) == "v2026.06.18"
    assert choose(rows, date(2026, 9, 3)) == "v2026.09.4"
    assert choose(rows, date(2026, 10, 17)) == "v2026.09.4"
    assert choose([{"tag_name": "v1", "published_at": "not-a-date"}], date(2026, 1, 1)) is None
    assert choose([{"tag_name": ""}], date(2026, 1, 1)) is None
    assert choose(["skip"], date(2026, 1, 1)) is None


def test_release_script_prints_the_tag_or_none(tmp_path: Path, capsys):
    module = _release_module()
    releases = SKILL / "references" / "releases.json"
    assert module.main([str(releases), "2026-08-01"]) == 0
    assert capsys.readouterr().out.strip() == "v2026.06.18"
    assert module.main([str(releases), "2026-06-17"]) == 0
    assert capsys.readouterr().out.strip() == "none"
    missing = tmp_path / "missing.json"
    assert module.main([str(missing), "2026-08-01"]) == 2
    assert capsys.readouterr().out.strip() == "none"
    assert module.main([str(releases), "August"]) == 2
    assert capsys.readouterr().out.strip() == "none"


def test_shipped_release_list_matches_the_connector_snapshot():
    skill_list = json.loads((SKILL / "references" / "releases.json").read_text(encoding="utf-8"))
    connector_list = json.loads(CONNECTOR_RELEASES.read_text(encoding="utf-8"))
    assert skill_list == connector_list
    note = (SKILL / "references" / "release-selection.md").read_text(encoding="utf-8")
    for row in skill_list["releases"]:
        assert row["tag_name"] in note
        assert row["published_at"][:10] in note
    assert "Do not parse the date from the tag" in note


def test_eval_cases_cover_the_release_edge_cases():
    loaded = harness.load_eval_file(EVALS)
    assert loaded.skill == "ism-control-lookup"
    assert [case.id for case in loaded.cases] == [
        "ism-1173",
        "missing-ism-9999",
        "mfa-protected",
        "june-september-2026",
        "in-force-2026-08-01",
        "injection-not-acted-on",
        "release-missing",
        "before-first-release",
        "id-with-space",
    ]
