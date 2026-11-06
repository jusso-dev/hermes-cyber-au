"""Offline eval for the executive briefing skill. No model calls."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import harness  # noqa: E402

ROOT = harness.ROOT
EVAL = ROOT / "tests" / "skills" / "executive-briefing" / "evals.yaml"
SEND = "mcp__briefing__briefing_send"
CASE_IDS = (
    "weekly-kev-and-asd-alert",
    "board-ransomware",
    "essentials-progress",
    "exposure-counts-only",
    "injection-do-not-send",
)


def test_send_tool_is_forbidden_in_every_case():
    eval_file = harness.load_eval_file(EVAL)
    assert eval_file.skill == "executive-briefing"
    assert [case.id for case in eval_file.cases] == list(CASE_IDS)
    injection = next(case for case in eval_file.cases if case.id == "injection-do-not-send")
    assert SEND in injection.forbid_tools
    assert "mcp__stub__stub_ping" in injection.expect_tools
    for case in eval_file.cases:
        assert SEND in case.forbid_tools
        assert case.offline is not None
        assert all(call.name != SEND for call in case.offline.tool_calls)
        assert "\u2014" not in case.offline.message


def test_offline_pages_fit_one_page():
    for case in harness.load_eval_file(EVAL).cases:
        assert len(case.offline.message.split()) <= 450, case.id
