"""SOCI deadline arithmetic and the offline skill eval. No model and no network."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "skills" / "soci-reporting" / "scripts" / "deadlines.py"
EVAL = ROOT / "tests" / "skills" / "soci-reporting" / "evals.yaml"
HARNESS = ROOT / "tests" / "skills" / "harness.py"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


deadlines = _load_module(SCRIPT, "soci_deadlines")
harness = _load_module(HARNESS, "soci_skill_harness")


def test_spring_forward_adds_hours_in_utc_then_returns_to_sydney():
    """12 hours from 20:00 AEST the evening before the October change is 09:00 AEDT."""
    start = deadlines.parse_moment("2026-10-03T20:00:00+10:00")
    due = deadlines.add_hours(start, 12)
    assert deadlines.format_sydney(due) == "2026-10-04T09:00:00+11:00"
    # Same-zone subtraction ignores the offset, so compare the UTC instants.
    assert due.astimezone(UTC) - start.astimezone(UTC) == timedelta(hours=12)
    assert due.utcoffset() == timedelta(hours=11)

    wall = (start.replace(tzinfo=None) + timedelta(hours=12)).replace(tzinfo=deadlines.SYDNEY)
    assert deadlines.format_sydney(wall) == "2026-10-04T08:00:00+11:00"
    assert deadlines.format_sydney(due) != deadlines.format_sydney(wall)


def test_autumn_change_adds_hours_in_utc_then_returns_to_sydney():
    """12 hours from 20:00 AEDT the evening before the April change is 07:00 AEST."""
    start = deadlines.parse_moment("2026-04-04T20:00:00+11:00")
    due = deadlines.add_hours(start, 12)
    assert deadlines.format_sydney(due) == "2026-04-05T07:00:00+10:00"
    assert due.astimezone(UTC) - start.astimezone(UTC) == timedelta(hours=12)
    assert due.utcoffset() == timedelta(hours=10)

    wall = (start.replace(tzinfo=None) + timedelta(hours=12)).replace(tzinfo=deadlines.SYDNEY)
    assert deadlines.format_sydney(due) != deadlines.format_sydney(wall)


def test_other_incident_seventy_two_hours_in_winter():
    result = deadlines.compute_deadlines("other_incident", "2026-06-15T09:00:00+10:00")
    assert result["section"] == "30BD"
    assert result["report_hours"] == 72
    assert result["report_due"] == "2026-06-18T09:00:00+10:00"
    assert result["written_record_due"] is None
    assert result["method"] == "add hours in UTC, then convert to Australia/Sydney"


def test_seventy_two_hours_across_the_october_change():
    result = deadlines.compute_deadlines("other_incident", "2026-10-03T20:00:00+10:00")
    assert result["report_due"] == "2026-10-06T21:00:00+11:00"
    start = deadlines.parse_moment(result["aware_at"])
    due = deadlines.parse_moment(result["report_due"])
    assert due.astimezone(UTC) - start.astimezone(UTC) == timedelta(hours=72)


def test_written_record_runs_from_the_oral_report_not_from_awareness():
    critical = deadlines.compute_deadlines(
        "critical_incident",
        "2026-10-03T20:00:00+10:00",
        oral_at="2026-10-03T20:00:00+10:00",
    )
    assert critical["report_due"] == "2026-10-04T09:00:00+11:00"
    assert critical["written_record_hours"] == 84
    assert critical["written_record_anchor"] == "oral_report"
    assert critical["written_record_due"] == "2026-10-07T09:00:00+11:00"

    later_oral = deadlines.compute_deadlines(
        "critical_incident",
        "2026-10-03T20:00:00+10:00",
        oral_at="2026-10-04T01:00:00+10:00",
    )
    assert later_oral["written_record_due"] == "2026-10-07T14:00:00+11:00"
    assert later_oral["written_record_due"] != critical["written_record_due"]

    other = deadlines.compute_deadlines(
        "other_incident",
        "2026-06-15T09:00:00+10:00",
        oral_at="2026-06-15T09:00:00+10:00",
    )
    assert other["written_record_hours"] == 48
    assert other["written_record_due"] == "2026-06-17T09:00:00+10:00"


def test_oral_report_before_awareness_is_rejected_and_a_late_oral_report_is_flagged():
    with pytest.raises(ValueError, match="before the entity became aware"):
        deadlines.compute_deadlines(
            "critical_incident",
            "2026-10-03T20:00:00+10:00",
            oral_at="2026-10-03T19:59:00+10:00",
        )
    on_time = deadlines.compute_deadlines(
        "critical_incident",
        "2026-10-03T20:00:00+10:00",
        oral_at="2026-10-04T09:00:00+11:00",
    )
    assert on_time["oral_after_report_due"] is False
    late = deadlines.compute_deadlines(
        "critical_incident",
        "2026-10-03T20:00:00+10:00",
        oral_at="2026-10-04T09:01:00+11:00",
    )
    assert late["oral_after_report_due"] is True
    assert late["written_record_due"] == "2026-10-07T21:01:00+11:00"
    no_oral = deadlines.compute_deadlines("critical_incident", "2026-10-03T20:00:00+10:00")
    assert no_oral["oral_after_report_due"] is None


def test_helper_runs_on_python_before_3_11():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "from datetime import UTC" not in source


def test_gap_and_fold_need_an_offset():
    with pytest.raises(ValueError, match="does not exist"):
        deadlines.parse_moment("2026-10-04T02:30:00")
    with pytest.raises(ValueError, match="ambiguous"):
        deadlines.parse_moment("2026-04-05T02:30:00")

    first = deadlines.parse_moment("2026-04-05T02:30:00+11:00")
    second = deadlines.parse_moment("2026-04-05T02:30:00+10:00")
    assert first.utcoffset() == timedelta(hours=11)
    assert second.utcoffset() == timedelta(hours=10)
    assert second.astimezone(UTC) - first.astimezone(UTC) == timedelta(hours=1)


def test_utc_z_suffix_converts_to_sydney():
    before = deadlines.parse_moment("2026-10-03T10:00:00Z")
    assert deadlines.format_sydney(before) == "2026-10-03T20:00:00+10:00"
    after = deadlines.parse_moment("2026-10-04T00:00:00Z")
    assert deadlines.format_sydney(after) == "2026-10-04T11:00:00+11:00"


def test_cli_prints_the_spring_forward_deadline(capsys: pytest.CaptureFixture[str]):
    code = deadlines.main(
        ["--trigger", "critical_incident", "--aware-at", "2026-10-03T20:00:00+10:00"]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["report_due"] == "2026-10-04T09:00:00+11:00"
    assert payload["written_record_due"] is None


def test_cli_rejects_a_nonexistent_sydney_time(capsys: pytest.CaptureFixture[str]):
    code = deadlines.main(["--trigger", "critical_incident", "--aware-at", "2026-10-04T02:30:00"])
    assert code == 2
    assert "does not exist" in capsys.readouterr().err


def test_helper_does_not_touch_the_network_or_submit():
    source = SCRIPT.read_text(encoding="utf-8")
    for banned in ("urllib", "socket", "http.client", "requests", "httpx"):
        assert banned not in source
    assert "def submit" not in source


def test_eval_deadlines_match_the_helper_and_forbid_submission():
    loaded = harness.load_eval_file(EVAL)
    by_id = {case.id: case for case in loaded.cases}
    critical = deadlines.compute_deadlines("critical_incident", "2026-10-03T20:00:00+10:00")
    other = deadlines.compute_deadlines("other_incident", "2026-06-15T09:00:00+10:00")

    assert critical["report_due"] in by_id["electricity-ot-outage"].offline.message
    assert critical["report_due"] in by_id["do-not-submit"].offline.message
    assert other["report_due"] in by_id["bank-it-compromise"].offline.message
    coverage = by_id["coverage-unknown"].offline.message
    assert critical["report_due"] not in coverage
    assert other["report_due"] not in coverage

    assert any("submit_report" in tool for case in loaded.cases for tool in case.forbid_tools)
    for case in loaded.cases:
        assert case.offline is not None
        assert all("submit" not in call.name for call in case.offline.tool_calls)


def test_offline_eval_scores_with_no_model(monkeypatch: pytest.MonkeyPatch):
    for name in harness.PROVIDER_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("CYBERAU_EVAL_MODELS", raising=False)
    result = harness.run_eval_file(EVAL, live=False)
    assert result["model_matrix"]["ran"] is False
    assert result["ok"], result
