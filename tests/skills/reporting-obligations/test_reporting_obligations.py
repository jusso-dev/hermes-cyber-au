"""reporting-obligations: scenarios match the engine, evals are current and pass offline."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
HARNESS = ROOT / "tests" / "skills" / "harness.py"
SCRIPT = ROOT / "skills" / "reporting-obligations" / "scripts" / "check_obligations.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


build = _load(HERE / "build_evals.py", "reporting_obligations_build_evals")
harness = _load(HARNESS, "reporting_obligations_harness")
SCENARIOS = build.load_scenarios()


def test_at_least_ten_scenarios_across_sectors():
    assert len(SCENARIOS) >= 10
    sectors = {s["org"]["sector"] for s in SCENARIOS}
    assert len(sectors) >= 8, sectors


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
def test_scenario_expected_obligations(scenario):
    result = build.result_for(scenario)
    found = build.groups(result)
    expect = scenario["expect"]
    for group in ("applicable", "possible", "limited_use"):
        if group in expect:
            assert found[group] == sorted(expect[group]), group
    for rule_id in expect.get("not_applicable_includes", []):
        assert rule_id in found["not_applicable"], rule_id
    assert result["submitted"] is False
    assert "not legal advice" in result["disclaimer"]


def test_evals_file_is_generated_from_the_current_engine():
    assert build.main([]) == 0, "run build_evals.py --write"


def test_evals_pass_offline():
    eval_file = harness.load_eval_file(HERE / "evals.yaml")
    assert eval_file.skill == "reporting-obligations"
    assert len(eval_file.cases) >= 11
    for case in eval_file.cases:
        assert case.offline is not None
        assert harness.score_session(case, case.offline) == [], case.id


def test_submitting_session_fails_the_eval():
    eval_file = harness.load_eval_file(HERE / "evals.yaml")
    case = eval_file.cases[0]
    bad = harness.Session(
        message=case.offline.message.replace("Nothing has been submitted", "The report submitted"),
        tool_calls=[harness.ToolCall("mcp__aureg__aureg_submit", {})],
    )
    failures = harness.score_session(case, bad)
    assert any("forbidden tool" in f for f in failures)
    assert any("missing fact" in f for f in failures)


def test_script_cli_prints_text_and_json(tmp_path):
    facts = tmp_path / "facts.json"
    facts.write_text(json.dumps({"ransomware_payment_made": True}), encoding="utf-8")
    org = tmp_path / "org.yaml"
    org.write_text("sector: retail\nturnover: 3m-or-more\n", encoding="utf-8")
    base = [sys.executable, str(SCRIPT), "--discovered-at", "2026-10-03T20:00:00+10:00"]
    text = subprocess.run(
        [*base, "--facts", str(facts), "--org", str(org)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "not legal advice" in text
    assert "2026-10-06T21:00:00+11:00" in text
    raw = subprocess.run(
        [*base, "--facts", str(facts), "--org", str(org), "--json"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert json.loads(raw)["submitted"] is False
    bad = subprocess.run(
        [sys.executable, str(SCRIPT), "--discovered-at", "not a time"],
        capture_output=True,
        text=True,
    )
    assert bad.returncode == 1
