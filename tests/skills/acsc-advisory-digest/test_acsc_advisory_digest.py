"""Offline checks for the ACSC advisory digest skill. No model calls."""

from __future__ import annotations

import importlib.util
import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import harness  # noqa: E402

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


def test_skill_structure():
    assert harness.check_skill(SKILL) == []


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
    assert period.proposed_watermark(today=today, fetch_ok=True, previous=watermark) == today
    assert period.proposed_watermark(today=today, fetch_ok=False, previous=watermark) is None
    assert (
        period.proposed_watermark(today=today, fetch_ok=True, previous=date(2026, 10, 16)) == today
    )


def test_offline_eval_passes_without_a_provider_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    for name in harness.PROVIDER_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("CYBERAU_EVAL_MODELS", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))

    def boom(*_args, **_kwargs):
        raise AssertionError("hermes was called")

    monkeypatch.setattr(harness, "run_hermes", boom)
    result = harness.run_eval_file(EVAL, live=False)
    failed = [case for case in result["cases"] if not case["ok"]]
    assert not failed, failed
    assert result["model_matrix"]["reason"] == "skipped: offline run"
