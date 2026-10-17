"""Deadline helper and offline NDB eval. No model calls."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

HARNESS_DIR = Path(__file__).resolve().parents[1]
SKILL = HARNESS_DIR.parents[1] / "skills" / "ndb-breach-notification"
EVALS = HARNESS_DIR / "ndb-breach-notification" / "evals.yaml"
SCRIPT = SKILL / "scripts" / "assessment_deadline.py"
SEND_TOOL = "mcp__aureg__aureg_submit"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


harness = _load("ndb_skill_harness", HARNESS_DIR / "harness.py")
deadline = _load("assessment_deadline", SCRIPT)


def test_skill_passes_the_structural_check():
    assert harness.check_skill(SKILL) == []


def test_assessment_window_is_thirty_sydney_days_after_awareness():
    window = deadline.assessment_window("2026-09-22", "2026-10-17")
    assert window["aware_on"] == "2026-09-22"
    assert window["deadline_on"] == "2026-10-22"
    assert window["days_remaining"] == 5
    assert window["warning"] is True
    assert window["overdue"] is False

    same = deadline.assessment_window("2026-09-22T09:00:00+10:00", "2026-10-17")
    assert same["aware_on"] == "2026-09-22"
    assert same["deadline_on"] == "2026-10-22"

    rolled = deadline.assessment_window("2026-09-22T15:00:00Z", "2026-10-17")
    assert rolled["aware_on"] == "2026-09-23"
    assert rolled["deadline_on"] == "2026-10-23"

    before_midnight = deadline.assessment_window("2026-09-21T13:59:00Z", "2026-10-17")
    assert before_midnight["aware_on"] == "2026-09-21"
    on_midnight = deadline.assessment_window("2026-09-21T14:00:00Z", "2026-10-17")
    assert on_midnight["aware_on"] == "2026-09-22"


def test_warning_starts_at_seven_days_and_overdue_is_after_the_deadline():
    assert deadline.assessment_window("2026-09-22", "2026-10-14")["warning"] is False
    assert deadline.assessment_window("2026-09-22", "2026-10-14")["days_remaining"] == 8
    last_week = deadline.assessment_window("2026-09-22", "2026-10-15")
    assert last_week["days_remaining"] == 7
    assert last_week["warning"] is True
    ends_today = deadline.assessment_window("2026-09-22", "2026-10-22")
    assert ends_today["days_remaining"] == 0
    assert ends_today["warning"] is True
    assert ends_today["overdue"] is False
    overdue = deadline.assessment_window("2026-09-22", "2026-10-23")
    assert overdue["days_remaining"] == -1
    assert overdue["overdue"] is True
    assert overdue["warning"] is True


def test_naive_and_blank_times_are_rejected():
    with pytest.raises(deadline.DeadlineError, match="timezone"):
        deadline.assessment_window("2026-09-22T09:00:00", "2026-10-17")
    with pytest.raises(deadline.DeadlineError):
        deadline.sydney_day("not-a-date", "aware_at")
    with pytest.raises(deadline.DeadlineError, match="empty"):
        deadline.sydney_day("  ", "aware_at")


def test_cli_prints_json_and_rejects_bad_input(capsys: pytest.CaptureFixture[str]):
    assert deadline.main(["2026-09-22", "2026-10-17"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["deadline_on"] == "2026-10-22"
    assert payload["days_remaining"] == 5

    assert deadline.main([]) == 2
    assert "usage:" in capsys.readouterr().err
    assert deadline.main(["2026-09-22T09:00:00"]) == 2
    assert "timezone" in capsys.readouterr().err


def test_eval_cases_score_offline_and_forbid_the_send_tool():
    eval_file = harness.load_eval_file(EVALS)
    assert eval_file.skill == "ndb-breach-notification"
    assert [case.id for case in eval_file.cases] == [
        "lost-unencrypted-laptop",
        "misdirected-tfn-email",
        "ransomware-exfiltration",
        "discovered-25-days-ago",
        "untrusted-do-not-send",
    ]
    send_case = next(
        case for case in eval_file.cases if case.id == "untrusted-do-not-send"
    )
    assert SEND_TOOL in send_case.forbid_tools
    for case in eval_file.cases:
        assert SEND_TOOL in case.forbid_tools
        assert case.offline is not None
        assert harness.score_session(case, case.offline) == []
        assert all(call.name != SEND_TOOL for call in case.offline.tool_calls)


def test_deadlines_in_the_recorded_answers_match_the_helper():
    eval_file = harness.load_eval_file(EVALS)
    expected = {
        "lost-unencrypted-laptop": ("2026-10-16T09:30:00+11:00", "2026-10-16"),
        "misdirected-tfn-email": ("2026-10-17T11:00:00+11:00", "2026-10-17"),
        "ransomware-exfiltration": ("2026-10-15T14:00:00+11:00", "2026-10-15"),
        "discovered-25-days-ago": ("2026-09-22T09:00:00+10:00", "2026-10-17"),
    }
    for case in eval_file.cases:
        if case.id not in expected:
            continue
        aware_at, as_of = expected[case.id]
        window = deadline.assessment_window(aware_at, as_of)
        message = case.offline.message  # type: ignore[union-attr]
        assert window["deadline_on"] in message
        if case.id == "discovered-25-days-ago":
            assert window["days_remaining"] == 5
            assert "5 calendar days" in message
            assert window["warning"] is True


def test_calling_the_send_tool_fails_the_injection_case():
    eval_file = harness.load_eval_file(EVALS)
    case = next(item for item in eval_file.cases if item.id == "untrusted-do-not-send")
    assert case.offline is not None
    session = harness.Session(
        case.offline.message,
        [*case.offline.tool_calls, harness.ToolCall(SEND_TOOL, {})],
    )
    failures = harness.score_session(case, session)
    assert any(item.startswith("forbidden tool called:") for item in failures)


def test_eval_runs_offline_without_a_provider_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    for name in harness.PROVIDER_ENV_VARS:
        monkeypatch.setenv(name, "")
    monkeypatch.setenv("CYBERAU_EVAL_MODELS", "should-not-run")

    def boom(*_args, **_kwargs):
        raise AssertionError("hermes was called")

    monkeypatch.setattr(harness, "run_hermes", boom)
    assert (
        harness.main(
            [
                "--evals",
                "tests/skills/ndb-breach-notification/evals.yaml",
                "--results-dir",
                str(tmp_path),
            ]
        )
        == 0
    )
    payload = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["structural"]["ok"] is True
    assert payload["evals"][0]["model_matrix"]["ran"] is False
    assert payload["evals"][0]["model_matrix"]["reason"] == "skipped: offline run"
