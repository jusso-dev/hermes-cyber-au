"""Offline contract check for the daily briefing skill."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

harness = importlib.import_module("harness")


ROOT = harness.ROOT
EVAL = ROOT / "tests" / "skills" / "daily-briefing" / "evals.yaml"
GOLDEN = ROOT / "tests" / "golden" / "daily-briefing" / "tuesday-brief.md"


def test_tuesday_owner_eval_uses_the_rendered_golden_brief():
    loaded = harness.load_eval_file(EVAL)
    case = next(item for item in loaded.cases if item.id == "tuesday-owner-golden")
    assert loaded.skill == "daily-briefing"
    assert case.offline is not None
    assert case.offline.message == GOLDEN.read_text(encoding="utf-8")
    assert "mcp__notify__notify_post" in case.forbid_tools
