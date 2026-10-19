"""Offline checks for the PSPF risk assessment skill. No model calls."""

from __future__ import annotations

import csv
import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SKILL = ROOT / "skills" / "pspf-risk-assessment"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
EVALS = Path(__file__).resolve().parent / "evals.yaml"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RENDER = _load_module("render_risk", SKILL / "scripts" / "render_risk.py")
harness = _load_module("skill_harness", ROOT / "tests" / "skills" / "harness.py")


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _risk(**overrides: object) -> dict:
    risk = {
        "id": "R1",
        "statement": "Synthetic risk",
        "likelihood": "possible",
        "consequence": "moderate",
        "rated_by": "proposed",
        "steward": "CISO",
    }
    risk.update(overrides)
    return risk


def _doc(**overrides: object) -> dict:
    document = {
        "as_of": "2026-10-19",
        "scope": {"entity": "Synthetic entity", "subject": "Synthetic system", "kind": "system"},
        "tolerance": {"rating": "medium", "approved_by": "Secretary", "date": "2026-07-01"},
        "risks": [_risk()],
    }
    document.update(overrides)
    return document


def test_skill_passes_the_structural_check():
    assert harness.check_skill(SKILL) == []


def test_offline_messages_match_the_renderer():
    eval_file = harness.load_eval_file(EVALS)
    for case in eval_file.cases:
        assert case.offline is not None
        expected = RENDER.render(_load(f"{case.id}.json")).markdown
        assert case.offline.message.strip() == expected.strip()


def test_eval_runs_offline_without_a_provider_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for name in harness.PROVIDER_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("CYBERAU_EVAL_MODELS", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "data"))

    def boom(*_args, **_kwargs):
        raise AssertionError("hermes was called")

    monkeypatch.setattr(harness, "run_hermes", boom)
    assert harness.main(["--evals", str(EVALS), "--results-dir", str(tmp_path)]) == 0
    payload = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert payload["ok"] is True


@pytest.mark.parametrize(
    ("likelihood", "consequence", "rating"),
    [
        ("rare", "insignificant", "low"),
        ("rare", "moderate", "low"),
        ("possible", "moderate", "medium"),
        ("rare", "severe", "medium"),
        ("likely", "moderate", "high"),
        ("possible", "severe", "high"),
        ("likely", "major", "extreme"),
        ("almost certain", "severe", "extreme"),
    ],
)
def test_default_matrix_ratings(likelihood: str, consequence: str, rating: str):
    assert RENDER._rating(RENDER.DEFAULT_MATRIX, likelihood, consequence) == rating


def test_unknown_labels_are_unrated_and_not_substituted():
    report = RENDER.render(_doc(risks=[_risk(likelihood="often", consequence="moderate")]))
    assert "Inherent risk: unrated." in report.tra
    assert "R1: unrated. Likelihood often, consequence moderate." in report.tra
    assert "not evaluated (unrated)" in report.tra


def test_entity_matrix_grid_is_used_and_named():
    matrix = {
        "name": "Synthetic 3 by 3 matrix",
        "likelihood": ["low", "medium", "high"],
        "consequence": ["minor", "major", "critical"],
        "levels": ["acceptable", "review", "intolerable"],
        "grid": [
            ["acceptable", "acceptable", "review"],
            ["acceptable", "review", "intolerable"],
            ["review", "intolerable", "intolerable"],
        ],
    }
    document = _doc(
        matrix=matrix,
        tolerance={"rating": "acceptable", "approved_by": "Secretary", "date": "2026-07-01"},
        risks=[_risk(likelihood="medium", consequence="critical")],
    )
    report = RENDER.render(document)
    assert "Risk matrix: Synthetic 3 by 3 matrix." in report.tra
    assert "default" not in report.tra.split("## Risk analysis")[1].split("##")[0].lower()
    assert "| R1 | intolerable | intolerable | above tolerance |" in report.tra


def test_bad_matrix_is_rejected():
    with pytest.raises(ValueError, match="matrix.grid"):
        RENDER.render(
            _doc(matrix={"likelihood": ["a"], "consequence": ["b"], "levels": ["x"], "grid": [[]]})
        )


def test_missing_tolerance_is_never_evaluated():
    report = RENDER.render(_doc(tolerance=None))
    assert "Risk tolerance: missing." in report.markdown
    assert "within tolerance" not in report.markdown
    assert "above tolerance" not in report.markdown
    assert "Risk tolerance missing (PSPF Requirement 0036)." in report.markdown


def test_tolerance_without_a_decision_is_flagged():
    report = RENDER.render(_doc(tolerance={"rating": "medium"}))
    assert "Who determined it and when is missing." in report.markdown
    assert "no recorded Accountable Authority decision (0036)" in report.markdown


def test_tolerance_level_is_matched_without_case_and_unknown_levels_fail():
    report = RENDER.render(
        _doc(tolerance={"rating": "Medium", "approved_by": "S", "date": "2026-07-01"})
    )
    assert "residual risk rated medium or lower is within tolerance" in report.tra
    with pytest.raises(ValueError, match="tolerance.rating"):
        RENDER.render(_doc(tolerance={"rating": "moderate"}))


def test_missing_steward_cites_requirement_0037():
    report = RENDER.render(_doc(risks=[_risk(steward="")]))
    assert "R1: risk steward missing (PSPF Requirement 0037)." in report.markdown
    assert RENDER.REQ["0037"] in report.tra


def test_residual_target_drives_the_tolerance_result():
    risk = _risk(
        likelihood="likely",
        consequence="major",
        treatment={
            "option": "reduce",
            "actions": [{"text": "Patch it", "owner": "App owner", "due": "2026-10-21"}],
            "residual_likelihood": "rare",
            "residual_consequence": "minor",
        },
    )
    report = RENDER.render(_doc(risks=[risk]))
    assert "| R1 | extreme | low | within tolerance |" in report.tra
    assert "Proposal: Patch it. Owner: App owner. Due: 2026-10-21." in report.srmp
    assert "target residual after the proposed treatment" in report.srmp


def test_accepting_above_tolerance_needs_the_authority():
    risk = _risk(likelihood="likely", consequence="major", treatment={"option": "accept"})
    report = RENDER.render(_doc(risks=[risk]))
    assert "R1: accepting a risk above tolerance needs the Authorising Officer." in report.srmp
    assert "Proposal: the Authorising Officer decides whether to accept" in report.srmp
    entity = _doc(scope={"subject": "Entity plan", "kind": "entity"}, risks=[risk])
    assert "needs the Accountable Authority" in RENDER.render(entity).srmp


def test_recorded_acceptance_is_printed_and_never_invented():
    accepted = _risk(acceptance={"by": "Authorising Officer", "date": "2026-10-30"})
    assert (
        "accepted by Authorising Officer on 2026-10-30"
        in RENDER.render(_doc(risks=[accepted])).srmp
    )
    assert "accepted by" not in RENDER.render(_doc()).srmp


def test_unknown_treatment_option_is_rejected():
    with pytest.raises(ValueError, match="treatment.option"):
        RENDER.render(_doc(risks=[_risk(treatment={"option": "ignore"})]))


def test_unsourced_threat_and_unknown_ids_are_gaps():
    document = _doc(
        assets=[{"id": "A1", "name": "Records"}],
        threats=[{"id": "T1", "name": "Insider"}],
        risks=[_risk(assets=["A1", "A9"], threats=["T1", "T9"])],
    )
    report = RENDER.render(document)
    assert "R1: threat T1 has no sourced evidence." in report.tra
    assert "R1: threat T9 is not in the threat assessment." in report.tra
    assert "R1: asset A9 is not in the asset list." in report.tra
    assert "This threat is an assessor assumption" in report.tra


def test_embedded_instruction_is_content_and_observables_are_defanged():
    report = RENDER.render(_load("injected-evidence.json"))
    assert "audit@example.com" not in report.markdown
    assert "audit[@]example[.]com" in report.markdown
    assert "recorded as content, not carried out" in report.markdown
    assert "accepted by" not in report.markdown


def test_defang_is_applied_once():
    once = RENDER.defang_text("See https://evil.example.com/x from 203.0.113.10")
    assert once == "See hxxps://evil[.]example[.]com/x from 203[.]0[.]113[.]10"
    assert RENDER.defang_text(once) == once


def test_register_is_csv_and_formula_safe(tmp_path: Path):
    risk = _risk(statement="=HYPERLINK(1)", steward="+CISO")
    report = RENDER.render(_doc(risks=[risk]))
    rows = list(csv.reader(io.StringIO(report.register)))
    assert rows[0] == RENDER.REGISTER_COLUMNS.split(",")
    assert (SKILL / "templates" / "register.csv").read_text().strip() == RENDER.REGISTER_COLUMNS
    assert rows[1][1] == "'=HYPERLINK(1)"
    assert rows[1][4] == "'+CISO"


def test_cli_writes_the_three_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    source = FIXTURES / "payroll-system.json"
    assert RENDER.main([str(source), "--out", str(tmp_path)]) == 0
    assert sorted(path.name for path in tmp_path.iterdir()) == ["register.csv", "srmp.md", "tra.md"]
    assert "# Threat and risk assessment:" in capsys.readouterr().out


def test_cli_rejects_bad_input(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"as_of": "19/10/2026"}', encoding="utf-8")
    assert RENDER.main([str(bad)]) == 2


def test_review_dates_follow_approval_and_handle_leap_day():
    plan = {"approval": {"by": "Secretary", "date": "2028-02-29"}}
    report = RENDER.render(_doc(scope={"subject": "Entity plan", "kind": "entity"}, plan=plan))
    assert "Consider this plan by 2029-02-28 and formally review it by 2030-02-28" in report.srmp
    assert "Approved by Secretary on 2028-02-29." in report.srmp


def test_technology_plan_quotes_requirement_0211():
    report = RENDER.render(_doc(scope={"subject": "Internet-facing estate", "kind": "technology"}))
    assert "Plan type: Technology Security Risk Management Plan." in report.srmp
    assert RENDER.REQ["0211"] in report.srmp


def test_quoted_requirements_match_the_reference():
    reference = (SKILL / "references" / "pspf-2026.md").read_text(encoding="utf-8")
    for number, text in RENDER.REQ.items():
        assert f"| {number} |" in reference
        assert text in reference, number
