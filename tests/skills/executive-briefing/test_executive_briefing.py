"""Offline eval for the executive briefing skill. No model calls."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import harness  # noqa: E402

ROOT = harness.ROOT
EVAL = ROOT / "tests" / "skills" / "executive-briefing" / "evals.yaml"
SKILL = ROOT / "skills" / "executive-briefing"
SEND = "mcp__briefing__briefing_send"
CASE_IDS = (
    "weekly-kev-and-asd-alert",
    "board-ransomware",
    "essentials-progress",
    "injection-do-not-send",
)


def test_skill_passes_structural_check():
    assert harness.check_skill(SKILL) == []


def test_eval_runs_offline_without_a_provider_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for name in harness.PROVIDER_ENV_VARS:
        monkeypatch.setenv(name, "")
    monkeypatch.setenv("CYBERAU_EVAL_MODELS", "should-not-run")

    def boom(*_args, **_kwargs):
        raise AssertionError("hermes was called")

    monkeypatch.setattr(harness, "run_hermes", boom)
    assert harness.main(["--evals", str(EVAL), "--results-dir", str(tmp_path)]) == 0
    payload = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["structural"]["ok"] is True
    run = payload["evals"][0]
    assert run["model_matrix"] == {"ran": False, "reason": "skipped: offline run", "models": []}
    assert [case["id"] for case in run["cases"]] == list(CASE_IDS)
    for case in run["cases"]:
        assert case["ok"] is True
        assert SEND not in case["tools_called"]


def test_send_tool_is_forbidden_in_every_case():
    eval_file = harness.load_eval_file(EVAL)
    assert eval_file.skill == "executive-briefing"
    injection = next(case for case in eval_file.cases if case.id == "injection-do-not-send")
    assert SEND in injection.forbid_tools
    assert "mcp__stub__stub_ping" in injection.expect_tools
    for case in eval_file.cases:
        assert SEND in case.forbid_tools
        assert case.offline is not None
        assert all(call.name != SEND for call in case.offline.tool_calls)
        assert "\u2014" not in case.offline.message
