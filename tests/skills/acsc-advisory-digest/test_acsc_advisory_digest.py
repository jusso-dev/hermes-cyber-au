"""Offline checks for the ACSC advisory digest skill. No model calls."""

from __future__ import annotations

import importlib.util
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import harness

ROOT = harness.ROOT
SKILL = ROOT / "skills" / "acsc-advisory-digest"
EVAL = ROOT / "tests" / "skills" / "acsc-advisory-digest" / "evals.yaml"
NOTIFY = "mcp__notify__notify_post"
CASE_IDS = {
    "two-alerts-one-advisory",
    "nothing-new",
    "feed-timeout",
    "kev-listed-cve",
    "injection-not-acted-on",
}


def _period():
    path = SKILL / "scripts" / "period.py"
    spec = importlib.util.spec_from_file_location("acsc_advisory_digest_period", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_skill_keeps_advisory_text_untrusted_and_does_not_post():
    text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    assert "untrusted" in text
    assert "notify_post" in text
    assert "Proposal:" in text
    assert "routine_state" in text
    assert "\u2014" not in text


def test_eval_cases_and_the_notify_tool():
    loaded = harness.load_eval_file(EVAL)
    assert loaded.skill == "acsc-advisory-digest"
    assert {case.id for case in loaded.cases} == CASE_IDS
    for case in loaded.cases:
        assert NOTIFY in case.forbid_tools
        assert case.offline is not None
        assert all(
            not harness.forbidden_tool_called(NOTIFY, call.name) for call in case.offline.tool_calls
        )


def test_period_window():
    period = _period()
    watermark = date(2026, 10, 1)
    today = date(2026, 10, 17)
    assert period.since_date(watermark) == date(2026, 10, 2)
    yesterday = date(2026, 10, 16)
    assert period.proposed_watermark(today=today, fetch_ok=True, previous=watermark) == yesterday
    assert period.proposed_watermark(today=today, fetch_ok=False, previous=watermark) is None
    assert period.proposed_watermark(today=today, fetch_ok=True, previous=yesterday) == yesterday
    assert period.proposed_watermark(today=today, fetch_ok=True, previous=today) is None
