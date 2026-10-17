"""ISM control lookup: date rule, structure, and the offline eval. No model."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import date
from pathlib import Path

HARNESS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HARNESS_DIR))

import harness

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
    releases = json.loads(
        (SKILL / "references" / "releases.json").read_text(encoding="utf-8")
    )
    rows = releases["releases"]
    assert choose(rows, date(2026, 6, 17)) is None
    assert choose(rows, date(2026, 6, 18)) == "v2026.06.18"
    assert choose(rows, date(2026, 8, 1)) == "v2026.06.18"
    assert choose(rows, date(2026, 9, 2)) == "v2026.06.18"
    assert choose(rows, date(2026, 9, 3)) == "v2026.09.4"
    assert choose(rows, date(2026, 10, 17)) == "v2026.09.4"
    assert (
        choose([{"tag_name": "v1", "published_at": "not-a-date"}], date(2026, 1, 1))
        is None
    )
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
    skill_list = json.loads(
        (SKILL / "references" / "releases.json").read_text(encoding="utf-8")
    )
    connector_list = json.loads(CONNECTOR_RELEASES.read_text(encoding="utf-8"))
    assert skill_list == connector_list
    note = (SKILL / "references" / "release-selection.md").read_text(encoding="utf-8")
    for row in skill_list["releases"]:
        assert row["tag_name"] in note
        assert row["published_at"][:10] in note
    assert "Do not parse the date from the tag" in note


def test_skill_passes_the_structural_check():
    assert harness.check_skill(SKILL) == []


def test_eval_scores_offline_without_a_provider_key(tmp_path: Path, monkeypatch):
    for name in harness.PROVIDER_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("CYBERAU_EVAL_MODELS", raising=False)
    monkeypatch.delenv("CYBERAU_ISM_SNAPSHOT", raising=False)
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "data"))

    def boom(*_args, **_kwargs):
        raise AssertionError("hermes was called")

    monkeypatch.setattr(harness, "run_hermes", boom)
    assert (
        harness.main(
            [
                "--evals",
                str(EVALS.relative_to(ROOT)),
                "--results-dir",
                str(tmp_path),
            ]
        )
        == 0
    )
    payload = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["evals"][0]["model_matrix"]["ran"] is False
    assert [case["id"] for case in payload["evals"][0]["cases"]] == [
        "ism-1173",
        "missing-ism-9999",
        "mfa-protected",
        "june-september-2026",
        "in-force-2026-08-01",
        "injection-not-acted-on",
    ]
